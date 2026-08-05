use std::{collections::HashMap, net::IpAddr, sync::Arc, time::Duration};

use futures_util::{SinkExt, StreamExt};
use nostr::PublicKey;
use serde::{Deserialize, Serialize};
use tauri::{ipc::Channel, plugin::TauriPlugin, Manager, Runtime};
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio_tungstenite::{
    connect_async,
    tungstenite::{
        client::IntoClientRequest,
        protocol::{frame::coding::CloseCode, CloseFrame, Message},
    },
};
use tokio_util::sync::CancellationToken;
use url::{Host, Url};

use buzz_core_pkg::client_binding_bootstrap::ClientBindingEpoch;

use crate::{
    app_state::AppState,
    client_binding_status_session::{
        is_reserved_text, ClientBindingStatusSession, CurrentProjection, ProjectionUpdate,
    },
};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_millis(250);
const SEND_QUEUE_CAPACITY: usize = 64;
const NIP11_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_NIP11_BODY_BYTES: usize = 64 * 1024;

pub(crate) fn install_crypto_provider() {
    // Dependencies enable both rustls providers; choose one before TLS setup.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

type Id = u32;

#[derive(Debug, Deserialize)]
#[serde(tag = "type", content = "data")]
pub(crate) enum WebSocketMessage {
    Text(String),
    Binary(Vec<u8>),
    Ping(Vec<u8>),
    Pong(Vec<u8>),
    Close(Option<CloseFramePayload>),
}

#[derive(Debug, Deserialize)]
pub(crate) struct CloseFramePayload {
    code: u16,
    reason: String,
}

impl From<WebSocketMessage> for Message {
    fn from(message: WebSocketMessage) -> Self {
        match message {
            WebSocketMessage::Text(value) => Message::Text(value.into()),
            WebSocketMessage::Binary(value) => Message::Binary(value.into()),
            WebSocketMessage::Ping(value) => Message::Ping(value.into()),
            WebSocketMessage::Pong(value) => Message::Pong(value.into()),
            WebSocketMessage::Close(frame) => Message::Close(frame.map(|frame| CloseFrame {
                code: CloseCode::from(frame.code),
                reason: frame.reason.into(),
            })),
        }
    }
}

#[derive(Serialize)]
#[serde(tag = "type", content = "data")]
enum OutboundMessage {
    Text(String),
    Binary(Vec<u8>),
    Ping(Vec<u8>),
    Pong(Vec<u8>),
    Close(Option<CloseFramePayloadOut>),
    Error(String),
}

#[derive(Serialize)]
struct CloseFramePayloadOut {
    code: u16,
    reason: String,
}

struct SendRequest {
    message: Message,
    result: oneshot::Sender<Result<(), String>>,
}

struct ConnectionHandle {
    sender: mpsc::Sender<SendRequest>,
    cancel: CancellationToken,
    task: Mutex<Option<tauri::async_runtime::JoinHandle<()>>>,
    status_scope: Mutex<Option<StatusScope>>,
}

struct StatusScope {
    relay_url: String,
    relay_signer: PublicKey,
    expected_author: PublicKey,
    epoch: ClientBindingEpoch,
    projection_channel: Channel<serde_json::Value>,
    generation: u64,
    challenge: Option<String>,
    auth_proven: bool,
}

struct PreparedStatus {
    session: ClientBindingStatusSession,
    scope: StatusScope,
}

pub(crate) struct StatusAuthProof {
    handle: Arc<ConnectionHandle>,
    challenge: String,
    relay_url: String,
    relay_signer: PublicKey,
    expected_author: PublicKey,
    epoch: ClientBindingEpoch,
    generation: u64,
}

impl StatusAuthProof {
    pub(crate) fn connection_epoch(&self) -> &ClientBindingEpoch {
        &self.epoch
    }

    pub(crate) const fn relay_signer(&self) -> PublicKey {
        self.relay_signer
    }
}

struct ProjectionOwner {
    id: Id,
    handle: Arc<ConnectionHandle>,
    epoch: ClientBindingEpoch,
    channel: Channel<serde_json::Value>,
}

#[derive(Default)]
struct ProjectionState {
    generation: u64,
    suspended: bool,
    owner: Option<ProjectionOwner>,
    current: Option<CurrentProjection>,
}

#[derive(Clone)]
pub(crate) struct WebSocketManager {
    connections: Arc<Mutex<HashMap<Id, Arc<ConnectionHandle>>>>,
    connect_cancel: Arc<Mutex<CancellationToken>>,
    projection: Arc<Mutex<ProjectionState>>,
}

impl Default for WebSocketManager {
    fn default() -> Self {
        Self {
            connections: Arc::default(),
            connect_cancel: Arc::new(Mutex::new(CancellationToken::new())),
            projection: Arc::default(),
        }
    }
}

impl WebSocketManager {
    async fn remove(&self, id: Id) -> Option<Arc<ConnectionHandle>> {
        self.connections.lock().await.remove(&id)
    }

    async fn remove_if_current(&self, id: Id, handle: &Arc<ConnectionHandle>) {
        let mut connections = self.connections.lock().await;
        if connections
            .get(&id)
            .is_some_and(|current| Arc::ptr_eq(current, handle))
        {
            connections.remove(&id);
        }
    }

    async fn projection_generation(&self) -> u64 {
        self.projection.lock().await.generation
    }

    async fn status_generation(&self) -> Option<u64> {
        let projection = self.projection.lock().await;
        (!projection.suspended).then_some(projection.generation)
    }

    async fn current_connect_cancel(&self) -> CancellationToken {
        self.connect_cancel.lock().await.clone()
    }

    async fn activate_projection_after_auth(&self, id: Id, proof: &StatusAuthProof) -> bool {
        if !self
            .connections
            .lock()
            .await
            .get(&id)
            .is_some_and(|current| Arc::ptr_eq(current, &proof.handle))
        {
            return false;
        }
        let mut projection = self.projection.lock().await;
        if projection.suspended || projection.generation != proof.generation {
            return false;
        }
        let mut status_scope = proof.handle.status_scope.lock().await;
        let Some(scope) = status_scope.as_mut() else {
            return false;
        };
        if scope.generation != proof.generation
            || scope.auth_proven
            || scope.challenge.as_deref() != Some(proof.challenge.as_str())
            || scope.relay_url != proof.relay_url
            || scope.relay_signer != proof.relay_signer
            || scope.expected_author != proof.expected_author
            || scope.epoch != proof.epoch
        {
            return false;
        }
        scope.auth_proven = true;
        if let Some(previous) = projection.owner.take() {
            let _ = previous.channel.send(serde_json::Value::Null);
        }
        projection.current = None;
        let _ = scope.projection_channel.send(serde_json::Value::Null);
        projection.owner = Some(ProjectionOwner {
            id,
            handle: Arc::clone(&proof.handle),
            epoch: proof.epoch.clone(),
            channel: scope.projection_channel.clone(),
        });
        true
    }

    async fn apply_projection_update(
        &self,
        id: Id,
        handle: &Arc<ConnectionHandle>,
        epoch: &ClientBindingEpoch,
        update: ProjectionUpdate,
    ) {
        if matches!(update, ProjectionUpdate::Unchanged) {
            return;
        }
        let mut projection = self.projection.lock().await;
        let Some(owner) = projection.owner.as_ref() else {
            return;
        };
        if owner.id != id || !Arc::ptr_eq(&owner.handle, handle) || owner.epoch != *epoch {
            return;
        }
        projection.current = match update {
            ProjectionUpdate::Current(current) => Some(current),
            ProjectionUpdate::Clear | ProjectionUpdate::Unchanged => None,
        };
        let value = projection
            .current
            .as_ref()
            .and_then(|current| serde_json::to_value(current).ok())
            .unwrap_or(serde_json::Value::Null);
        if let Some(owner) = projection.owner.as_ref() {
            let _ = owner.channel.send(value);
        }
    }

    async fn clear_projection_if_owner(
        &self,
        id: Id,
        handle: &Arc<ConnectionHandle>,
        epoch: &ClientBindingEpoch,
    ) {
        let mut projection = self.projection.lock().await;
        if projection.owner.as_ref().is_some_and(|owner| {
            owner.id == id && Arc::ptr_eq(&owner.handle, handle) && owner.epoch == *epoch
        }) {
            if let Some(owner) = projection.owner.take() {
                let _ = owner.channel.send(serde_json::Value::Null);
            }
            projection.current = None;
        }
    }

    /// Invalidate all browser-visible status and revoke the current socket's
    /// ownership. Late work from that socket is rejected by the owner fence.
    pub(crate) async fn invalidate_projection(&self) {
        {
            let mut projection = self.projection.lock().await;
            projection.generation = projection.generation.wrapping_add(1);
            if let Some(owner) = projection.owner.take() {
                let _ = owner.channel.send(serde_json::Value::Null);
            }
            projection.current = None;
        }
        self.cancel_status_connections().await;
    }

    /// Permanently disable status projection for the remainder of this process.
    /// Sign-out uses this before starting restart so no racing webview request
    /// can regain presentation ownership with the retiring identity.
    pub(crate) async fn suspend_projection(&self) {
        {
            let mut projection = self.projection.lock().await;
            projection.suspended = true;
            projection.generation = projection.generation.wrapping_add(1);
            if let Some(owner) = projection.owner.take() {
                let _ = owner.channel.send(serde_json::Value::Null);
            }
            projection.current = None;
        }
        self.cancel_status_connections().await;
    }

    async fn cancel_status_connections(&self) {
        let handles = self
            .connections
            .lock()
            .await
            .values()
            .cloned()
            .collect::<Vec<_>>();
        for handle in handles {
            if handle.status_scope.lock().await.take().is_some() {
                handle.cancel.cancel();
            }
        }
    }

    async fn record_status_challenge(
        &self,
        id: Id,
        handle: &Arc<ConnectionHandle>,
        challenge: &str,
    ) {
        if !self
            .connections
            .lock()
            .await
            .get(&id)
            .is_some_and(|current| Arc::ptr_eq(current, handle))
        {
            return;
        }
        let mut status_scope = handle.status_scope.lock().await;
        let Some(scope) = status_scope.as_mut() else {
            return;
        };
        match scope.challenge.as_deref() {
            None => scope.challenge = Some(challenge.to_owned()),
            Some(existing) if existing == challenge => {}
            Some(_) => {
                status_scope.take();
            }
        }
    }

    pub(crate) async fn status_auth_proof(
        &self,
        id: Id,
        challenge: &str,
        relay_url: &str,
        expected_author: PublicKey,
    ) -> Result<StatusAuthProof, String> {
        let handle = self
            .connections
            .lock()
            .await
            .get(&id)
            .cloned()
            .ok_or_else(|| "native WebSocket is not current".to_string())?;
        let current_generation = self
            .status_generation()
            .await
            .ok_or_else(|| "native WebSocket status is suspended".to_string())?;
        let scope = handle.status_scope.lock().await;
        let scope = scope
            .as_ref()
            .ok_or_else(|| "native WebSocket is not status-capable".to_string())?;
        if scope.auth_proven
            || scope.challenge.as_deref() != Some(challenge)
            || scope.relay_url != relay_url
            || scope.expected_author != expected_author
            || scope.generation != current_generation
        {
            return Err("native WebSocket status scope does not match".to_string());
        }
        Ok(StatusAuthProof {
            handle: Arc::clone(&handle),
            challenge: challenge.to_owned(),
            relay_url: scope.relay_url.clone(),
            relay_signer: scope.relay_signer,
            expected_author: scope.expected_author,
            epoch: scope.epoch.clone(),
            generation: scope.generation,
        })
    }

    pub(crate) async fn complete_status_auth(
        &self,
        id: Id,
        proof: &StatusAuthProof,
    ) -> Result<(), String> {
        if self.activate_projection_after_auth(id, proof).await {
            Ok(())
        } else {
            Err("native WebSocket status scope changed while signing".to_string())
        }
    }

    async fn disconnect_handle(handle: Arc<ConnectionHandle>) {
        handle.cancel.cancel();
        if let Some(mut task) = handle.task.lock().await.take() {
            if tokio::time::timeout(SHUTDOWN_TIMEOUT, &mut task)
                .await
                .is_err()
            {
                task.abort();
                let _ = task.await;
            }
        }
    }

    async fn disconnect(&self, id: Id) {
        if let Some(handle) = self.remove(id).await {
            let owner_epoch = self
                .projection
                .lock()
                .await
                .owner
                .as_ref()
                .filter(|owner| owner.id == id && Arc::ptr_eq(&owner.handle, &handle))
                .map(|owner| owner.epoch.clone());
            if let Some(epoch) = owner_epoch {
                self.clear_projection_if_owner(id, &handle, &epoch).await;
            }
            Self::disconnect_handle(handle).await;
        }
    }

    async fn disconnect_all(&self) {
        self.invalidate_projection().await;
        let mut connect_cancel = self.connect_cancel.lock().await;
        connect_cancel.cancel();
        *connect_cancel = CancellationToken::new();
        let handles = {
            let mut connections = self.connections.lock().await;
            connections
                .drain()
                .map(|(_, handle)| handle)
                .collect::<Vec<_>>()
        };
        futures_util::future::join_all(handles.into_iter().map(Self::disconnect_handle)).await;
    }
}

#[cfg(test)]
async fn open_connection(
    manager: &WebSocketManager,
    url: &str,
    on_message: Channel<serde_json::Value>,
) -> Result<Id, String> {
    let connect_cancel = manager.current_connect_cancel().await;
    open_connection_with_projection(manager, url, on_message, None, connect_cancel).await
}

async fn open_connection_with_projection(
    manager: &WebSocketManager,
    url: &str,
    on_message: Channel<serde_json::Value>,
    prepared_status: Option<PreparedStatus>,
    connect_cancel: CancellationToken,
) -> Result<Id, String> {
    let request = url
        .into_client_request()
        .map_err(|error| error.to_string())?;
    let (socket, _) = tokio::select! {
        _ = connect_cancel.cancelled() => return Err("WebSocket connection cancelled".to_string()),
        result = tokio::time::timeout(CONNECT_TIMEOUT, connect_async(request)) => result
            .map_err(|_| "WebSocket connection timed out".to_string())?
            .map_err(|error| error.to_string())?,
    };

    // Serialize registration with disconnect_all so a reload cannot miss a
    // connection that finished its handshake concurrently with teardown.
    let current_connect_cancel = manager.connect_cancel.lock().await;
    if connect_cancel.is_cancelled() {
        return Err("WebSocket connection cancelled".to_string());
    }
    let current_generation = manager.projection_generation().await;
    if prepared_status
        .as_ref()
        .is_some_and(|prepared| prepared.scope.generation != current_generation)
    {
        return Err("WebSocket connection scope changed".to_string());
    }

    let id = loop {
        let candidate = uuid::Uuid::new_v4().as_u128() as u32;
        if !manager.connections.lock().await.contains_key(&candidate) {
            break candidate;
        }
    };
    let (sender, receiver) = mpsc::channel(SEND_QUEUE_CAPACITY);
    let cancel = CancellationToken::new();
    let handle = Arc::new(ConnectionHandle {
        sender,
        cancel: cancel.clone(),
        task: Mutex::new(None),
        status_scope: Mutex::new(prepared_status.as_ref().map(|prepared| StatusScope {
            relay_url: prepared.scope.relay_url.clone(),
            relay_signer: prepared.scope.relay_signer,
            expected_author: prepared.scope.expected_author,
            epoch: prepared.scope.epoch.clone(),
            projection_channel: prepared.scope.projection_channel.clone(),
            generation: prepared.scope.generation,
            challenge: None,
            auth_proven: false,
        })),
    });
    let mut task_slot = handle.task.lock().await;
    manager.connections.lock().await.insert(id, handle.clone());

    let registered_generation = manager.projection_generation().await;
    if prepared_status
        .as_ref()
        .is_some_and(|prepared| prepared.scope.generation != registered_generation)
    {
        manager.remove_if_current(id, &handle).await;
        handle.cancel.cancel();
        return Err("WebSocket connection scope changed".to_string());
    }

    let status_session = prepared_status.map(|prepared| prepared.session);

    let task_manager = manager.clone();
    let task = tauri::async_runtime::spawn(run_connection_inner(
        id,
        socket,
        receiver,
        cancel,
        on_message,
        task_manager,
        handle.clone(),
        status_session,
    ));
    *task_slot = Some(task);
    drop(task_slot);
    drop(current_connect_cancel);
    Ok(id)
}

#[tauri::command]
async fn connect(
    manager: tauri::State<'_, WebSocketManager>,
    state: tauri::State<'_, AppState>,
    url: String,
    on_message: Channel<serde_json::Value>,
    on_projection: Option<Channel<serde_json::Value>>,
    _config: Option<serde_json::Value>,
) -> Result<Id, String> {
    let connect_cancel = manager.current_connect_cancel().await;
    let generation = manager.status_generation().await;
    let prepared_status = match (on_projection, generation) {
        (Some(channel), Some(generation)) => tokio::select! {
            _ = connect_cancel.cancelled() => {
                return Err("WebSocket connection cancelled".to_string());
            }
            prepared = prepare_status_session(&state, &url, channel, generation) => prepared,
        },
        _ => None,
    };
    if prepared_status.is_some()
        && manager.status_generation().await
            != prepared_status
                .as_ref()
                .map(|prepared| prepared.scope.generation)
    {
        return Err("WebSocket connection scope changed".to_string());
    }
    open_connection_with_projection(
        manager.inner(),
        &url,
        on_message,
        prepared_status,
        connect_cancel,
    )
    .await
}

async fn prepare_status_session(
    state: &AppState,
    requested_url: &str,
    projection_channel: Channel<serde_json::Value>,
    generation: u64,
) -> Option<PreparedStatus> {
    if requested_url != crate::relay::relay_ws_url_with_override(state) {
        return None;
    }
    let expected_author = state.signing_keys().ok()?.public_key();
    let relay_signer = fetch_nip11_signer(requested_url).await.ok()?;
    let epoch = ClientBindingEpoch::new_v4();
    Some(PreparedStatus {
        session: ClientBindingStatusSession::new(relay_signer, expected_author, epoch.clone()),
        scope: StatusScope {
            relay_url: requested_url.to_owned(),
            relay_signer,
            expected_author,
            epoch,
            projection_channel,
            generation,
            challenge: None,
            auth_proven: false,
        },
    })
}

#[derive(Deserialize)]
struct Nip11Identity {
    #[serde(rename = "self")]
    relay_self: String,
}

async fn fetch_nip11_signer(relay_url: &str) -> Result<PublicKey, String> {
    let url = nip11_url(relay_url)?;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(NIP11_TIMEOUT)
        .build()
        .map_err(|_| "NIP-11 unavailable".to_string())?;
    let response = client
        .get(url)
        .header(reqwest::header::ACCEPT, "application/nostr+json")
        .send()
        .await
        .map_err(|_| "NIP-11 unavailable".to_string())?;
    if !response.status().is_success()
        || response
            .content_length()
            .is_some_and(|length| length > MAX_NIP11_BODY_BYTES as u64)
    {
        return Err("NIP-11 unavailable".to_string());
    }
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| "NIP-11 unavailable".to_string())?;
        if body.len().saturating_add(chunk.len()) > MAX_NIP11_BODY_BYTES {
            return Err("NIP-11 unavailable".to_string());
        }
        body.extend_from_slice(&chunk);
    }
    let identity: Nip11Identity =
        serde_json::from_slice(&body).map_err(|_| "NIP-11 unavailable".to_string())?;
    if identity.relay_self.len() != 64
        || !identity
            .relay_self
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("NIP-11 unavailable".to_string());
    }
    PublicKey::from_hex(&identity.relay_self).map_err(|_| "NIP-11 unavailable".to_string())
}

fn nip11_url(relay_url: &str) -> Result<Url, String> {
    let mut url = Url::parse(relay_url).map_err(|_| "NIP-11 unavailable".to_string())?;
    match url.scheme() {
        "wss" => url
            .set_scheme("https")
            .map_err(|_| "NIP-11 unavailable".to_string())?,
        "ws" if is_loopback_url(&url) => url
            .set_scheme("http")
            .map_err(|_| "NIP-11 unavailable".to_string())?,
        _ => return Err("NIP-11 unavailable".to_string()),
    }
    Ok(url)
}

fn is_loopback_url(url: &Url) -> bool {
    match url.host() {
        Some(Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
        Some(Host::Ipv4(address)) => IpAddr::V4(address).is_loopback(),
        Some(Host::Ipv6(address)) => IpAddr::V6(address).is_loopback(),
        None => false,
    }
}

pub(crate) async fn send_message(
    manager: &WebSocketManager,
    id: Id,
    message: WebSocketMessage,
) -> Result<(), String> {
    // Egress guard: the NIP-49 local key backup must never reach a relay.
    // This is the single choke point for all webview-originated websocket
    // frames (see `crate::egress_guard`).
    match &message {
        WebSocketMessage::Text(text) => {
            crate::egress_guard::assert_no_key_backup(text, "websocket text frame")?
        }
        WebSocketMessage::Binary(bytes) => {
            crate::egress_guard::assert_no_key_backup_bytes(bytes, "websocket binary frame")?
        }
        _ => {}
    }
    let handle = manager
        .connections
        .lock()
        .await
        .get(&id)
        .cloned()
        .ok_or_else(|| format!("WebSocket connection {id} not found"))?;
    let (result_tx, result_rx) = oneshot::channel();
    tokio::time::timeout(
        WRITE_TIMEOUT,
        handle.sender.send(SendRequest {
            message: message.into(),
            result: result_tx,
        }),
    )
    .await
    .map_err(|_| "WebSocket send queue timed out".to_string())?
    .map_err(|_| "WebSocket connection closed".to_string())?;

    tokio::time::timeout(WRITE_TIMEOUT, result_rx)
        .await
        .map_err(|_| "WebSocket send timed out".to_string())?
        .map_err(|_| "WebSocket connection closed".to_string())?
}

#[tauri::command]
async fn send(
    manager: tauri::State<'_, WebSocketManager>,
    id: Id,
    message: WebSocketMessage,
) -> Result<(), String> {
    send_message(manager.inner(), id, message).await
}

#[tauri::command]
async fn disconnect(manager: tauri::State<'_, WebSocketManager>, id: Id) -> Result<(), String> {
    manager.disconnect(id).await;
    Ok(())
}

#[tauri::command]
async fn disconnect_all(manager: tauri::State<'_, WebSocketManager>) -> Result<(), String> {
    manager.disconnect_all().await;
    Ok(())
}

#[cfg(test)]
async fn run_connection<S>(
    id: Id,
    socket: tokio_tungstenite::WebSocketStream<S>,
    receiver: mpsc::Receiver<SendRequest>,
    cancel: CancellationToken,
    on_message: Channel<serde_json::Value>,
    manager: WebSocketManager,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let Some(handle) = manager.connections.lock().await.get(&id).cloned() else {
        return;
    };
    run_connection_inner(
        id, socket, receiver, cancel, on_message, manager, handle, None,
    )
    .await;
}

#[allow(clippy::too_many_arguments)]
async fn run_connection_inner<S>(
    id: Id,
    mut socket: tokio_tungstenite::WebSocketStream<S>,
    mut receiver: mpsc::Receiver<SendRequest>,
    cancel: CancellationToken,
    on_message: Channel<serde_json::Value>,
    manager: WebSocketManager,
    handle: Arc<ConnectionHandle>,
    mut status_session: Option<ClientBindingStatusSession>,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    loop {
        let expiry_delay = status_session
            .as_ref()
            .and_then(ClientBindingStatusSession::projected_fresh_until)
            .map(|fresh_until| Duration::from_secs(fresh_until.saturating_sub(unix_now())));
        let expiry = async {
            match expiry_delay {
                Some(delay) => tokio::time::sleep(delay).await,
                None => std::future::pending::<()>().await,
            }
        };
        tokio::select! {
            _ = expiry => {
                if let Some(session) = status_session.as_mut() {
                    let epoch = session.connection_epoch().clone();
                    let update = session.expire(unix_now());
                    manager.apply_projection_update(id, &handle, &epoch, update).await;
                }
            }
            _ = cancel.cancelled() => {
                let _ = tokio::time::timeout(
                    SHUTDOWN_TIMEOUT,
                    socket.send(Message::Close(Some(CloseFrame {
                        code: CloseCode::Normal,
                        reason: "disconnect".into(),
                    }))),
                ).await;
                break;
            }
            request = receiver.recv() => {
                let Some(request) = request else { break };
                let result = tokio::time::timeout(WRITE_TIMEOUT, socket.send(request.message))
                    .await
                    .map_err(|_| "WebSocket send timed out".to_string())
                    .and_then(|result| result.map_err(|error| error.to_string()));
                let failed = result.is_err();
                let _ = request.result.send(result);
                if failed { break; }
            }
            incoming = socket.next() => {
                let message = match incoming {
                    Some(Ok(message)) => {
                        if let Message::Text(text) = &message {
                            if let Some(challenge) = nip42_challenge(text) {
                                manager
                                    .record_status_challenge(id, &handle, &challenge)
                                    .await;
                            }
                        }
                        let reserved_text = reserved_text_message(&message);
                        if let Some(text) = reserved_text {
                            if let Some(mut session) = status_session.take() {
                                let epoch = session.connection_epoch().clone();
                                let folded = tauri::async_runtime::spawn_blocking(move || {
                                    let update = session.consume_text(&text, unix_now());
                                    (session, update)
                                })
                                .await;
                                match folded {
                                    Ok((returned_session, update)) => {
                                        status_session = Some(returned_session);
                                        if let Some(update) = update {
                                            manager
                                                .apply_projection_update(
                                                    id, &handle, &epoch, update,
                                                )
                                                .await;
                                        }
                                    }
                                    Err(_) => {
                                        manager
                                            .clear_projection_if_owner(id, &handle, &epoch)
                                            .await;
                                    }
                                }
                            }
                            continue;
                        }
                        outbound_message(message)
                    }
                    Some(Err(error)) => OutboundMessage::Error(error.to_string()),
                    None => OutboundMessage::Close(None),
                };
                let terminal = matches!(message, OutboundMessage::Close(_) | OutboundMessage::Error(_));
                if let Ok(value) = serde_json::to_value(message) {
                    let _ = on_message.send(value);
                }
                if terminal { break; }
            }
        }
    }
    if let Some(session) = status_session.as_mut() {
        let epoch = session.connection_epoch().clone();
        let update = session.disconnect();
        manager
            .apply_projection_update(id, &handle, &epoch, update)
            .await;
        manager.clear_projection_if_owner(id, &handle, &epoch).await;
    }
    manager.remove_if_current(id, &handle).await;
}

fn reserved_text_message(message: &Message) -> Option<String> {
    match message {
        Message::Text(value) if is_reserved_text(value) => Some(value.to_string()),
        _ => None,
    }
}

fn nip42_challenge(text: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(text).ok()?;
    let values = value.as_array()?;
    if values.len() != 2 || values.first().and_then(serde_json::Value::as_str) != Some("AUTH") {
        return None;
    }
    values.get(1)?.as_str().map(str::to_owned)
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

fn outbound_message(message: Message) -> OutboundMessage {
    match message {
        Message::Text(value) => OutboundMessage::Text(value.to_string()),
        Message::Binary(value) => OutboundMessage::Binary(value.to_vec()),
        Message::Ping(value) => OutboundMessage::Ping(value.to_vec()),
        Message::Pong(value) => OutboundMessage::Pong(value.to_vec()),
        Message::Close(frame) => OutboundMessage::Close(frame.map(|frame| CloseFramePayloadOut {
            code: frame.code.into(),
            reason: frame.reason.to_string(),
        })),
        Message::Frame(_) => OutboundMessage::Error("unexpected raw WebSocket frame".to_string()),
    }
}

pub fn init<R: Runtime>() -> TauriPlugin<R> {
    install_crypto_provider();
    tauri::plugin::Builder::new("websocket")
        .invoke_handler(tauri::generate_handler![
            connect,
            send,
            disconnect,
            disconnect_all
        ])
        .setup(|app, _api| {
            app.manage(WebSocketManager::default());
            Ok(())
        })
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::FutureExt;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use buzz_core_pkg::client_binding_bootstrap::{
        CLIENT_BINDING_BOOTSTRAP_SUB_ID, CLIENT_BINDING_STATUS_SUB_ID,
    };
    use tauri::ipc::InvokeResponseBody;
    use tokio::io::duplex;
    use tokio_tungstenite::{tungstenite::protocol::Role, WebSocketStream};

    fn silent_channel() -> Channel<serde_json::Value> {
        Channel::new(|_: InvokeResponseBody| Ok(()))
    }

    #[tokio::test]
    async fn secure_websocket_reaches_tls_without_panicking() {
        install_crypto_provider();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_millis(100)).await;
        });
        let result = std::panic::AssertUnwindSafe(tokio_tungstenite::connect_async(format!(
            "wss://{address}"
        )))
        .catch_unwind()
        .await;

        assert!(result.is_ok(), "TLS setup must not panic");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn live_tcp_server_connect_send_and_disconnect() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (received_tx, received_rx) = oneshot::channel();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
            let message = socket.next().await.unwrap().unwrap();
            received_tx.send(message).unwrap();
            while let Some(message) = socket.next().await {
                if matches!(message, Ok(Message::Close(_))) {
                    break;
                }
            }
        });

        let manager = WebSocketManager::default();
        let id = open_connection(&manager, &format!("ws://{address}"), silent_channel())
            .await
            .unwrap();
        send_message(&manager, id, WebSocketMessage::Text("live-probe".into()))
            .await
            .unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), received_rx)
                .await
                .unwrap()
                .unwrap(),
            Message::Text("live-probe".into())
        );

        manager.disconnect(id).await;
        assert!(!manager.connections.lock().await.contains_key(&id));
        tokio::time::timeout(Duration::from_secs(1), server)
            .await
            .expect("live server should observe native socket shutdown")
            .unwrap();
    }

    #[tokio::test]
    async fn eof_removes_connection() {
        let manager = WebSocketManager::default();
        let (client_io, server_io) = duplex(1024);
        let (client, server) = tokio::join!(
            WebSocketStream::from_raw_socket(client_io, Role::Client, None),
            WebSocketStream::from_raw_socket(server_io, Role::Server, None),
        );
        let (sender, receiver) = mpsc::channel(SEND_QUEUE_CAPACITY);
        let handle = Arc::new(ConnectionHandle {
            sender,
            cancel: CancellationToken::new(),
            task: Mutex::new(None),
            status_scope: Mutex::new(None),
        });
        manager.connections.lock().await.insert(1, handle.clone());
        let task = tauri::async_runtime::spawn(run_connection(
            1,
            client,
            receiver,
            handle.cancel.clone(),
            silent_channel(),
            manager.clone(),
        ));
        *handle.task.lock().await = Some(task);

        drop(server);
        tokio::time::timeout(Duration::from_secs(1), async {
            while manager.connections.lock().await.contains_key(&1) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("EOF should clean up its native connection ID");
    }

    #[tokio::test]
    async fn disconnect_removes_and_drops_task_before_returning() {
        struct DropGuard(Arc<AtomicBool>);
        impl Drop for DropGuard {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        let manager = WebSocketManager::default();
        let dropped = Arc::new(AtomicBool::new(false));
        let task_dropped = dropped.clone();
        let (ready_tx, ready_rx) = oneshot::channel();
        let (sender, _receiver) = mpsc::channel(SEND_QUEUE_CAPACITY);
        let handle = Arc::new(ConnectionHandle {
            sender,
            cancel: CancellationToken::new(),
            task: Mutex::new(Some(tauri::async_runtime::spawn(async move {
                let _guard = DropGuard(task_dropped);
                ready_tx.send(()).unwrap();
                std::future::pending::<()>().await;
            }))),
            status_scope: Mutex::new(None),
        });
        manager.connections.lock().await.insert(7, handle);
        ready_rx.await.unwrap();

        tokio::time::timeout(Duration::from_secs(1), manager.disconnect(7))
            .await
            .expect("disconnect should abort an unresponsive task");
        assert!(!manager.connections.lock().await.contains_key(&7));
        assert!(dropped.load(Ordering::SeqCst));

        // Repeated teardown is intentionally a no-op.
        manager.disconnect(7).await;
    }

    #[tokio::test]
    async fn teardown_gate_stays_closed_until_tasks_stop() {
        let manager = WebSocketManager::default();
        let gate = manager.connect_cancel.lock().await;
        let (sender, _receiver) = mpsc::channel(SEND_QUEUE_CAPACITY);
        let handle = Arc::new(ConnectionHandle {
            sender,
            cancel: CancellationToken::new(),
            task: Mutex::new(Some(tauri::async_runtime::spawn(async {
                std::future::pending::<()>().await;
            }))),
            status_scope: Mutex::new(None),
        });
        manager.connections.lock().await.insert(1, handle);
        gate.cancel();
        let handles = {
            let mut connections = manager.connections.lock().await;
            connections
                .drain()
                .map(|(_, handle)| handle)
                .collect::<Vec<_>>()
        };

        let shutdown = futures_util::future::join_all(
            handles.into_iter().map(WebSocketManager::disconnect_handle),
        );
        assert!(manager.connect_cancel.try_lock().is_err());
        shutdown.await;
        drop(gate);
        assert!(manager.connect_cancel.try_lock().is_ok());
    }

    #[tokio::test]
    async fn disconnect_all_cancels_pending_connect_generation() {
        let manager = WebSocketManager::default();
        let pending = manager.current_connect_cancel().await;
        let generation = manager.projection_generation().await;

        manager.disconnect_all().await;

        assert!(pending.is_cancelled());
        assert!(!manager.current_connect_cancel().await.is_cancelled());
        assert_ne!(manager.projection_generation().await, generation);
    }

    #[tokio::test]
    async fn one_connection_does_not_block_another_send_queue() {
        let manager = WebSocketManager::default();
        let (blocked_sender, blocked_receiver) = mpsc::channel(1);
        blocked_sender
            .send(SendRequest {
                message: Message::Text("blocked".into()),
                result: oneshot::channel().0,
            })
            .await
            .unwrap();
        let blocked = Arc::new(ConnectionHandle {
            sender: blocked_sender,
            cancel: CancellationToken::new(),
            task: Mutex::new(None),
            status_scope: Mutex::new(None),
        });
        manager.connections.lock().await.insert(1, blocked);

        let (healthy_sender, mut healthy_receiver) = mpsc::channel(1);
        let healthy = Arc::new(ConnectionHandle {
            sender: healthy_sender.clone(),
            cancel: CancellationToken::new(),
            task: Mutex::new(None),
            status_scope: Mutex::new(None),
        });
        manager.connections.lock().await.insert(2, healthy);

        let (result, _) = oneshot::channel();
        tokio::time::timeout(
            Duration::from_millis(50),
            healthy_sender.send(SendRequest {
                message: Message::Text("healthy".into()),
                result,
            }),
        )
        .await
        .expect("a full queue on one connection must not block another")
        .unwrap();
        assert!(healthy_receiver.recv().await.is_some());
        drop(blocked_receiver);
    }

    #[test]
    fn nip11_url_accepts_tls_or_loopback_only() {
        assert_eq!(
            nip11_url("wss://relay.example.test/community?view=1")
                .expect("secure relay URL is eligible")
                .as_str(),
            "https://relay.example.test/community?view=1"
        );
        assert_eq!(
            nip11_url("ws://localhost:3000/")
                .expect("localhost relay URL is eligible")
                .as_str(),
            "http://localhost:3000/"
        );
        assert!(nip11_url("ws://127.0.0.1:3000/").is_ok());
        assert!(nip11_url("ws://[::1]:3000/").is_ok());
        assert!(nip11_url("ws://relay.example.test/").is_err());
        assert!(nip11_url("http://localhost:3000/").is_err());

        assert!(is_loopback_url(
            &Url::parse("ws://LOCALHOST:3000/").expect("test URL")
        ));
        assert!(!is_loopback_url(
            &Url::parse("ws://localhost.example.test/").expect("test URL")
        ));
    }

    fn test_epoch(suffix: u8) -> ClientBindingEpoch {
        ClientBindingEpoch::parse(&format!("11111111-1111-4111-8111-{suffix:012x}"))
            .expect("synthetic epoch")
    }

    fn test_handle(status_scope: Option<StatusScope>) -> Arc<ConnectionHandle> {
        let (sender, _receiver) = mpsc::channel(SEND_QUEUE_CAPACITY);
        Arc::new(ConnectionHandle {
            sender,
            cancel: CancellationToken::new(),
            task: Mutex::new(None),
            status_scope: Mutex::new(status_scope),
        })
    }

    fn test_status_scope(
        generation: u64,
        relay: PublicKey,
        author: PublicKey,
        epoch: ClientBindingEpoch,
    ) -> StatusScope {
        StatusScope {
            relay_url: "ws://localhost:3000/".to_string(),
            relay_signer: relay,
            expected_author: author,
            epoch,
            projection_channel: silent_channel(),
            generation,
            challenge: None,
            auth_proven: false,
        }
    }

    #[tokio::test]
    async fn only_proven_status_socket_owns_projection_and_old_handle_is_fenced() {
        let manager = WebSocketManager::default();
        let relay = nostr::Keys::generate().public_key();
        let author = nostr::Keys::generate().public_key();
        let generation = manager.projection_generation().await;
        let old_epoch = test_epoch(0x11);
        let old = test_handle(Some(test_status_scope(
            generation,
            relay,
            author,
            old_epoch.clone(),
        )));
        manager.connections.lock().await.insert(7, old.clone());
        manager
            .record_status_challenge(7, &old, "challenge-old")
            .await;
        let old_proof = manager
            .status_auth_proof(7, "challenge-old", "ws://localhost:3000/", author)
            .await
            .expect("exact native proof");
        manager
            .complete_status_auth(7, &old_proof)
            .await
            .expect("old socket owns projection");

        let current = CurrentProjection {
            event_author_pubkey: author.to_hex(),
            fresh_until: u64::MAX,
            connection_epoch: old_epoch.as_str().to_owned(),
        };
        manager
            .apply_projection_update(
                7,
                &old,
                &old_epoch,
                ProjectionUpdate::Current(current.clone()),
            )
            .await;
        assert_eq!(manager.projection.lock().await.current, Some(current));

        assert!(manager
            .status_auth_proof(7, "challenge-old", "ws://wrong/", author)
            .await
            .is_err());
        assert!(manager.projection.lock().await.current.is_some());

        let new_epoch = test_epoch(0x22);
        let new = test_handle(Some(test_status_scope(
            generation,
            relay,
            author,
            new_epoch.clone(),
        )));
        manager.connections.lock().await.insert(7, new.clone());
        manager
            .record_status_challenge(7, &new, "challenge-new")
            .await;
        let new_proof = manager
            .status_auth_proof(7, "challenge-new", "ws://localhost:3000/", author)
            .await
            .expect("replacement proof");
        manager
            .complete_status_auth(7, &new_proof)
            .await
            .expect("replacement owns projection");
        manager.clear_projection_if_owner(7, &old, &old_epoch).await;
        manager
            .apply_projection_update(
                7,
                &old,
                &old_epoch,
                ProjectionUpdate::Current(CurrentProjection {
                    event_author_pubkey: "11".repeat(32),
                    fresh_until: u64::MAX,
                    connection_epoch: old_epoch.as_str().to_owned(),
                }),
            )
            .await;
        assert!(manager.projection.lock().await.current.is_none());

        let read_only = test_handle(None);
        manager
            .connections
            .lock()
            .await
            .insert(8, read_only.clone());
        assert!(manager
            .status_auth_proof(8, "challenge", "ws://localhost:3000/", author)
            .await
            .is_err());

        manager.invalidate_projection().await;
        assert!(new.cancel.is_cancelled());
        assert!(manager.projection.lock().await.owner.is_none());
        assert!(manager.complete_status_auth(7, &new_proof).await.is_err());
        manager.suspend_projection().await;
        assert!(manager.status_generation().await.is_none());
    }

    #[tokio::test]
    async fn stale_task_cannot_remove_reused_connection_id() {
        let manager = WebSocketManager::default();
        let (old_sender, _old_receiver) = mpsc::channel(SEND_QUEUE_CAPACITY);
        let old = Arc::new(ConnectionHandle {
            sender: old_sender,
            cancel: CancellationToken::new(),
            task: Mutex::new(None),
            status_scope: Mutex::new(None),
        });
        let (new_sender, _new_receiver) = mpsc::channel(SEND_QUEUE_CAPACITY);
        let current = Arc::new(ConnectionHandle {
            sender: new_sender,
            cancel: CancellationToken::new(),
            task: Mutex::new(None),
            status_scope: Mutex::new(None),
        });
        manager.connections.lock().await.insert(9, old.clone());
        manager.connections.lock().await.insert(9, current.clone());

        manager.remove_if_current(9, &old).await;
        assert!(manager
            .connections
            .lock()
            .await
            .get(&9)
            .is_some_and(|handle| Arc::ptr_eq(handle, &current)));
        manager.remove_if_current(9, &current).await;
        assert!(!manager.connections.lock().await.contains_key(&9));
    }

    #[tokio::test]
    async fn reserved_text_is_swallowed_but_binary_remains_raw_delivery() {
        let manager = WebSocketManager::default();
        let delivered = Arc::new(AtomicUsize::new(0));
        let delivered_for_channel = delivered.clone();
        let channel = Channel::new(move |_: InvokeResponseBody| {
            delivered_for_channel.fetch_add(1, Ordering::SeqCst);
            Ok(())
        });
        let (client_io, server_io) = duplex(4096);
        let (client, mut server) = tokio::join!(
            WebSocketStream::from_raw_socket(client_io, Role::Client, None),
            WebSocketStream::from_raw_socket(server_io, Role::Server, None),
        );
        let (sender, receiver) = mpsc::channel(SEND_QUEUE_CAPACITY);
        let handle = Arc::new(ConnectionHandle {
            sender,
            cancel: CancellationToken::new(),
            task: Mutex::new(None),
            status_scope: Mutex::new(None),
        });
        manager.connections.lock().await.insert(42, handle.clone());
        let task = tauri::async_runtime::spawn(run_connection(
            42,
            client,
            receiver,
            handle.cancel.clone(),
            channel,
            manager.clone(),
        ));
        *handle.task.lock().await = Some(task);

        server
            .send(Message::Text(
                serde_json::json!(["EVENT", CLIENT_BINDING_BOOTSTRAP_SUB_ID])
                    .to_string()
                    .into(),
            ))
            .await
            .expect("send reserved bootstrap frame");
        server
            .send(Message::Binary(
                serde_json::json!(["EVENT", CLIENT_BINDING_STATUS_SUB_ID, "malformed"])
                    .to_string()
                    .into_bytes()
                    .into(),
            ))
            .await
            .expect("send reserved status frame");
        server
            .send(Message::Text("ordinary".into()))
            .await
            .expect("send ordinary frame");
        server
            .send(Message::Close(None))
            .await
            .expect("close synthetic socket");

        let task = handle
            .task
            .lock()
            .await
            .take()
            .expect("connection task is registered");
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("connection loop exits")
            .expect("connection task joins");
        assert_eq!(
            delivered.load(Ordering::SeqCst),
            3,
            "binary, ordinary text, and terminal close reach raw delivery"
        );
        assert!(!manager.connections.lock().await.contains_key(&42));
    }

    #[test]
    fn reserved_classifier_never_intercepts_binary() {
        let reserved =
            serde_json::json!(["EVENT", CLIENT_BINDING_STATUS_SUB_ID, "malformed"]).to_string();
        assert!(reserved_text_message(&Message::Text(reserved.clone().into())).is_some());
        assert!(reserved_text_message(&Message::Binary(reserved.into_bytes().into())).is_none());
    }

    #[test]
    fn auth_challenge_recording_requires_exact_frame_shape() {
        assert_eq!(
            nip42_challenge(&serde_json::json!(["AUTH", "exact"]).to_string()).as_deref(),
            Some("exact")
        );
        assert!(
            nip42_challenge(&serde_json::json!(["AUTH", "exact", "extra"]).to_string()).is_none()
        );
        assert!(nip42_challenge("not-json").is_none());
    }
}
