from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from chimera_intel.core.negotiation_simulator import get_personas

router = APIRouter()
personas = get_personas()


@router.get("/simulator/personas")
async def get_available_personas():
    """Returns a list of available AI personas for the simulator."""
    return {
        key: {"name": p.name, "description": p.description}
        for key, p in personas.items()
    }


@router.websocket("/simulator/ws/{persona_key}")
async def simulator_websocket_endpoint(websocket: WebSocket, persona_key: str):
    """Handles the real-time negotiation simulation via WebSocket."""
    persona = personas.get(persona_key)
    if not persona:
        await websocket.close(code=1008)
        return

    await websocket.accept()
    history = []
    try:
        while True:
            user_message = await websocket.receive_text()
            history.append({"sender_id": "user", "content": user_message})

            # Get response from the selected AI persona
            response_data = persona.generate_response(user_message, history)
            history.append(
                {"sender_id": "ai", "content": response_data["persona_response"]}
            )

            await websocket.send_json(response_data)

    except WebSocketDisconnect:
        print(f"Client disconnected from '{persona.name}' simulation.")
    except Exception as e:
        print(f"An error occurred in the simulation: {e}")
    finally:
        await websocket.close()
