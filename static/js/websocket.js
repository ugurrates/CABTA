/**
 * Blue Team Assistant - WebSocket Client
 * Author: Ugur Ates
 *
 * Provides the BTAWebSocket class for real-time analysis progress updates.
 * Features: automatic reconnection (max 3 attempts), heartbeat handling,
 * and callback hooks for progress, completion, and failure events.
 * Vanilla JavaScript - no frameworks required.
 */

(function () {
    'use strict';

    /* --------------------------------------------------
       Constants
    -------------------------------------------------- */
    var MAX_RECONNECT_ATTEMPTS = 3;
    var RECONNECT_DELAY_MS = 2000;       // Initial delay, doubles on each retry
    var HEARTBEAT_INTERVAL_MS = 25000;   // Send ping every 25 seconds
    var HEARTBEAT_TIMEOUT_MS = 35000;    // Expect pong within 35 seconds

    /* --------------------------------------------------
       BTAWebSocket Class
    -------------------------------------------------- */

    /**
     * Create a new BTAWebSocket instance.
     * Usage:
     *   var ws = new BTAWebSocket();
     *   ws.onProgress  = function(data) { ... };
     *   ws.onCompleted = function(data) { ... };
     *   ws.onFailed    = function(data) { ... };
     *   ws.connect(analysisId);
     */
    function BTAWebSocket() {
        this._socket = null;
        this._analysisId = null;
        this._reconnectAttempts = 0;
        this._heartbeatTimer = null;
        this._heartbeatTimeout = null;
        this._intentionalClose = false;

        // Public callbacks (assign before calling connect)
        this.onProgress = null;
        this.onCompleted = null;
        this.onFailed = null;
        this.onConnected = null;
        this.onDisconnected = null;
    }

    /* --------------------------------------------------
       Public methods
    -------------------------------------------------- */

    /**
     * Open a WebSocket connection for the given analysis.
     * @param {string} analysisId - The analysis identifier to subscribe to.
     */
    BTAWebSocket.prototype.connect = function (analysisId) {
        if (!analysisId) {
            console.error('[BTAWebSocket] analysisId is required.');
            return;
        }

        this._analysisId = analysisId;
        this._intentionalClose = false;
        this._reconnectAttempts = 0;
        this._openSocket();
    };

    /**
     * Gracefully close the current connection. Will not trigger reconnection.
     */
    BTAWebSocket.prototype.disconnect = function () {
        this._intentionalClose = true;
        this._stopHeartbeat();
        if (this._socket) {
            this._socket.close(1000, 'Client disconnect');
            this._socket = null;
        }
    };

    /**
     * Send a JSON message through the open socket.
     * @param {Object} data - Payload to send.
     */
    BTAWebSocket.prototype.send = function (data) {
        if (!this._socket || this._socket.readyState !== WebSocket.OPEN) {
            console.warn('[BTAWebSocket] Cannot send, socket is not open.');
            return;
        }
        this._socket.send(JSON.stringify(data));
    };

    /**
     * Return true if the socket is currently open.
     */
    BTAWebSocket.prototype.isConnected = function () {
        return this._socket !== null && this._socket.readyState === WebSocket.OPEN;
    };

    /* --------------------------------------------------
       Internal methods
    -------------------------------------------------- */

    /**
     * Build the WebSocket URL using the current page's protocol/host.
     */
    BTAWebSocket.prototype._buildUrl = function () {
        var protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        var host = window.location.host;
        return protocol + '//' + host + '/ws/analysis/' + encodeURIComponent(this._analysisId);
    };

    /**
     * Create and configure the underlying WebSocket.
     */
    BTAWebSocket.prototype._openSocket = function () {
        var self = this;

        // Close any existing socket first
        if (this._socket) {
            try { this._socket.close(); } catch (e) { /* ignored */ }
        }

        var url = this._buildUrl();
        console.info('[BTAWebSocket] Connecting to', url, '(attempt ' + (this._reconnectAttempts + 1) + ')');

        try {
            this._socket = new WebSocket(url);
        } catch (err) {
            console.error('[BTAWebSocket] Failed to create WebSocket:', err.message);
            this._scheduleReconnect();
            return;
        }

        this._socket.onopen = function () {
            console.info('[BTAWebSocket] Connected.');
            self._reconnectAttempts = 0;
            self._startHeartbeat();

            if (typeof self.onConnected === 'function') {
                self.onConnected();
            }
        };

        this._socket.onmessage = function (event) {
            self._handleMessage(event);
        };

        this._socket.onerror = function (event) {
            console.error('[BTAWebSocket] Error:', event);
        };

        this._socket.onclose = function (event) {
            console.info('[BTAWebSocket] Closed (code=' + event.code + ', reason=' + event.reason + ')');
            self._stopHeartbeat();

            if (typeof self.onDisconnected === 'function') {
                self.onDisconnected(event);
            }

            if (!self._intentionalClose) {
                self._scheduleReconnect();
            }
        };
    };

    /**
     * Parse an incoming message and dispatch to the appropriate callback.
     * Expected message format: { type: "progress"|"completed"|"failed"|"pong", ... }
     */
    BTAWebSocket.prototype._handleMessage = function (event) {
        var data;
        try {
            data = JSON.parse(event.data);
        } catch (e) {
            console.warn('[BTAWebSocket] Non-JSON message received:', event.data);
            return;
        }

        var messageType = data.type || data.event || '';

        switch (messageType) {
            case 'progress':
                if (typeof this.onProgress === 'function') {
                    this.onProgress(data);
                }
                break;

            case 'completed':
                if (typeof this.onCompleted === 'function') {
                    this.onCompleted(data);
                }
                // Analysis is done; no need to keep the socket open
                this.disconnect();
                break;

            case 'failed':
            case 'error':
                if (typeof this.onFailed === 'function') {
                    this.onFailed(data);
                }
                this.disconnect();
                break;

            case 'pong':
                // Heartbeat acknowledged - clear the timeout
                this._clearHeartbeatTimeout();
                break;

            default:
                console.debug('[BTAWebSocket] Unhandled message type:', messageType, data);
                break;
        }
    };

    /* --------------------------------------------------
       Reconnection
    -------------------------------------------------- */

    /**
     * Schedule a reconnection attempt with exponential back-off.
     */
    BTAWebSocket.prototype._scheduleReconnect = function () {
        if (this._reconnectAttempts >= MAX_RECONNECT_ATTEMPTS) {
            console.warn('[BTAWebSocket] Max reconnect attempts (' + MAX_RECONNECT_ATTEMPTS + ') reached. Giving up.');
            return;
        }

        var delay = RECONNECT_DELAY_MS * Math.pow(2, this._reconnectAttempts);
        this._reconnectAttempts++;

        console.info('[BTAWebSocket] Reconnecting in ' + delay + 'ms (attempt ' + this._reconnectAttempts + '/' + MAX_RECONNECT_ATTEMPTS + ')');

        var self = this;
        setTimeout(function () {
            if (!self._intentionalClose) {
                self._openSocket();
            }
        }, delay);
    };

    /* --------------------------------------------------
       Heartbeat
    -------------------------------------------------- */

    /**
     * Start sending periodic ping messages to keep the connection alive.
     */
    BTAWebSocket.prototype._startHeartbeat = function () {
        this._stopHeartbeat();

        var self = this;
        this._heartbeatTimer = setInterval(function () {
            if (self._socket && self._socket.readyState === WebSocket.OPEN) {
                self.send({ type: 'ping' });
                self._setHeartbeatTimeout();
            }
        }, HEARTBEAT_INTERVAL_MS);
    };

    /**
     * Stop the heartbeat interval and any pending timeout.
     */
    BTAWebSocket.prototype._stopHeartbeat = function () {
        if (this._heartbeatTimer) {
            clearInterval(this._heartbeatTimer);
            this._heartbeatTimer = null;
        }
        this._clearHeartbeatTimeout();
    };

    /**
     * Set a timeout to detect if the server did not respond to a ping.
     */
    BTAWebSocket.prototype._setHeartbeatTimeout = function () {
        this._clearHeartbeatTimeout();

        var self = this;
        this._heartbeatTimeout = setTimeout(function () {
            console.warn('[BTAWebSocket] Heartbeat timeout - server unresponsive. Closing connection.');
            if (self._socket) {
                self._socket.close(4000, 'Heartbeat timeout');
            }
        }, HEARTBEAT_TIMEOUT_MS);
    };

    /**
     * Clear the heartbeat timeout (called when a pong is received).
     */
    BTAWebSocket.prototype._clearHeartbeatTimeout = function () {
        if (this._heartbeatTimeout) {
            clearTimeout(this._heartbeatTimeout);
            this._heartbeatTimeout = null;
        }
    };

    /* --------------------------------------------------
       Export
    -------------------------------------------------- */
    window.BTAWebSocket = BTAWebSocket;

})();
