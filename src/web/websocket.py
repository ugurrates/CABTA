"""
Author: Ugur Ates
WebSocket handler for real-time analysis progress.
"""

import asyncio
import json
import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

logger = logging.getLogger(__name__)
router = APIRouter()


@router.websocket('/ws/analysis/{analysis_id}')
async def analysis_ws(websocket: WebSocket, analysis_id: str):
    """WebSocket endpoint for real-time analysis progress updates.

    Client connects to ``/ws/analysis/{id}`` and receives JSON messages::

        {"type": "progress", "progress": 45, "step": "Querying VirusTotal..."}
        {"type": "completed", "verdict": "MALICIOUS", "score": 85}
        {"type": "failed", "error": "Timeout"}
    """
    await websocket.accept()

    mgr = websocket.app.state.analysis_manager
    queue = mgr.subscribe(analysis_id)

    try:
        # Send current status immediately
        job = mgr.get_job(analysis_id)
        if job:
            await websocket.send_json({
                'type': 'status',
                'status': job.get('status'),
                'progress': job.get('progress', 0),
                'step': job.get('current_step', ''),
            })

            # If already completed, send result and close
            if job.get('status') in ('completed', 'failed'):
                await websocket.send_json({
                    'type': job['status'],
                    'verdict': job.get('verdict'),
                    'score': job.get('score'),
                })
                await websocket.close()
                return

        # Stream updates
        while True:
            try:
                msg = await asyncio.wait_for(queue.get(), timeout=30.0)
                await websocket.send_json(msg)

                # Close after completion or failure
                if msg.get('type') in ('completed', 'failed'):
                    break
            except asyncio.TimeoutError:
                # Send heartbeat
                await websocket.send_json({'type': 'heartbeat'})

    except WebSocketDisconnect:
        logger.debug(f"[WS] Client disconnected: {analysis_id}")
    except Exception as exc:
        logger.debug(f"[WS] Error: {exc}")
    finally:
        mgr.unsubscribe(analysis_id, queue)


@router.websocket('/ws/agent/{session_id}')
async def agent_ws(websocket: WebSocket, session_id: str):
    """WebSocket endpoint for real-time agent investigation updates.

    Uses AgentLoop's pub/sub system for efficient event-driven updates
    instead of polling.
    """
    await websocket.accept()

    store = websocket.app.state.agent_store
    agent_loop = websocket.app.state.agent_loop
    if not store:
        await websocket.send_json({'type': 'error', 'error': 'Agent store not available'})
        await websocket.close()
        return

    # Send current session state immediately
    session = store.get_session(session_id)
    if not session:
        await websocket.send_json({'type': 'error', 'error': 'Session not found'})
        await websocket.close()
        return

    steps = store.get_steps(session_id)
    await websocket.send_json({
        'type': 'session_state',
        'session': session,
        'steps': steps,
    })

    # If already done, close
    if session.get('status') in ('completed', 'failed', 'cancelled'):
        await websocket.send_json({
            'type': session['status'],
            'summary': session.get('summary', ''),
        })
        await websocket.close()
        return

    # Use pub/sub if agent loop available, otherwise fall back to polling
    if agent_loop:
        queue = agent_loop.subscribe(session_id)
        try:
            while True:
                try:
                    msg = await asyncio.wait_for(queue.get(), timeout=15.0)
                    await websocket.send_json(msg)
                    if msg.get('type') in ('completed', 'failed', 'cancelled'):
                        break
                except asyncio.TimeoutError:
                    await websocket.send_json({'type': 'heartbeat'})
        except WebSocketDisconnect:
            logger.debug(f"[WS] Agent client disconnected: {session_id}")
        except Exception as exc:
            logger.debug(f"[WS] Agent WS error: {exc}")
        finally:
            agent_loop.unsubscribe(session_id, queue)
    else:
        # Fallback: poll store every 2s
        try:
            last_step_count = len(steps)
            while True:
                await asyncio.sleep(2)
                session = store.get_session(session_id)
                if not session:
                    break

                current_steps = store.get_steps(session_id)
                if len(current_steps) > last_step_count:
                    for step in current_steps[last_step_count:]:
                        await websocket.send_json({'type': 'step', 'step': step})
                    last_step_count = len(current_steps)

                if session.get('status') in ('completed', 'failed', 'cancelled'):
                    await websocket.send_json({
                        'type': session['status'],
                        'summary': session.get('summary', ''),
                    })
                    break

                await websocket.send_json({'type': 'heartbeat'})
        except WebSocketDisconnect:
            logger.debug(f"[WS] Agent client disconnected: {session_id}")
        except Exception as exc:
            logger.debug(f"[WS] Agent WS error: {exc}")
