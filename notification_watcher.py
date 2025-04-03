import requests
import time
import ssl
import os
import json
import uuid
import re
import gc
import threading
import queue

from pynostr.event import Event, EventKind
from pynostr.relay_manager import RelayManager
from pynostr.message_type import ClientMessageType
from pynostr.key import PrivateKey
from pynostr.key import PublicKey
from pynostr.filters import FiltersList, Filters
from pynostr.encrypted_dm import EncryptedDirectMessage
from pynostr.utils import get_timestamp

from datetime import datetime
from zoneinfo import ZoneInfo
from urllib.parse import urlparse, parse_qs

message_queue = queue.Queue()
running_flag = threading.Event()
running_flag.set()

def send_message_to_screen(message, url):
    params = {'message': message}
    headers = {'accept': 'application/json'}
    
    try:
        response = requests.post(url, params=params, headers=headers)
        response.raise_for_status()  # Raises an HTTPError for bad responses (4xx and 5xx)
        return response.json()
    except requests.exceptions.HTTPError as http_err:
        print(f'HTTP error occurred: {http_err}')
    except requests.exceptions.ConnectionError as conn_err:
        print(f'Connection error occurred: {conn_err}')
    except requests.exceptions.Timeout as timeout_err:
        print(f'Timeout error occurred: {timeout_err}')
    except requests.exceptions.RequestException as req_err:
        print(f'An error occurred: {req_err}')
    except ValueError as json_err:
        print(f'JSON decode error: {json_err}')
    return None

def consumer():
    url = os.environ['IDOTMATRIX']
    
    while running_flag.is_set():
        try:
            message = message_queue.get(timeout=1).strip()
            message = message[:80].upper() # Only send first 80 characters
            
            send_message_to_screen(message, url)
            
            message_queue.task_done()
        except queue.Empty:
            continue

# Extract the differents parts from the NWC connection string
def extract_parts(url):
    u = urlparse(url)
    q = parse_qs(u.query)
    return u.netloc, q.get('relay',[''])[0], q.get('secret',[''])[0]

# Parses notification event after decryption
def parse_nwc_notification(content):
    notification_type = json.loads(content)["notification_type"]    
    if notification_type == "payment_received":
        payment_type = "rcvd"
    elif notification_type == "payment_sent":
        payment_type = "sent"
    else:
        raise Exception("weird notification")

    n = json.loads(content)["notification"]
    
    if len(n["description"]) > 0:
        description = "(%s)" % n["description"]
    else:
        description = ""
    output = "%1.0f sats %s! %s" % ( n["amount"]/1000.0, payment_type, description)
    return output

# Connects to relay and start watching for notification events
def watch_for_notifications():
    nwc_string = os.environ['NWC']
    wallet_service_public_key, relay, secret = extract_parts(nwc_string)
    private_key = PrivateKey.from_hex(secret)
    print("Pubkey: " + private_key.public_key.bech32())
    print("Pubkey (hex): " + private_key.public_key.hex())

    relay_manager = RelayManager(timeout=2)
    relay_manager.add_relay(relay)

    start_timestamp = get_timestamp()-10.0

    # According to NIP47, kind 23196 is a notification event. Listen
    # only for events directed at my public key. 
    filters = FiltersList( [ Filters(
        pubkey_refs=[private_key.public_key.hex()],
        kinds=[23196], limit=1),] )    
    
    # List to store previously seen event ids
    messages_done = []
    
    while(True):
        subscription_id = uuid.uuid1().hex
        relay_manager.add_subscription_on_all_relays(subscription_id, filters)
        relay_manager.run_sync()
        
        while relay_manager.message_pool.has_notices():
            notice_msg = relay_manager.message_pool.get_notice()
            print("Notice: " + notice_msg.content)
            
        while relay_manager.message_pool.has_events():
            event_msg = relay_manager.message_pool.get_event()
            
            # Ignore previously seen events
            if(event_msg.event.id in messages_done):
                continue

            # Add this event to the list of seen events
            messages_done.append(event_msg.event.id)

            # According to NIP47, kind 23196 is a notification event
            if event_msg.event.kind == 23196:
                public_key = PublicKey(wallet_service_public_key)
                msg_decrypted = EncryptedDirectMessage()
                msg_decrypted.decrypt(private_key_hex=private_key.hex(),
                                      encrypted_message=event_msg.event.content,
                                      public_key_hex=public_key.hex())

                result = parse_nwc_notification(msg_decrypted.cleartext_content)
                message_queue.put(result)

            # This is not necessary. Kept it here for for debugging purposes
            elif event_msg.event.kind == EventKind.TEXT_NOTE:
                content = re.sub(r'\b(nostr:)?(nprofile|npub)[0-9a-z]+[\s]*', '', event_msg.event.content)

                if (len(content) < 4):
                    continue
                
                print(f"Received public note: {content}")
            
            gc.collect()

        time.sleep(2)
        relay_manager.close_all_relay_connections()

if __name__ == "__main__":
    consumer_thread = threading.Thread(target=consumer)
    consumer_thread.daemon = True
    consumer_thread.start()
    
    try:
        watch_for_notifications()
    except KeyboardInterrupt:
        running_flag.clear()
        print("\nStopping threads...")
    except Exception as err:
        print(f"Unexpected {err=}, {type(err)=}")
        relay_manager.close_all_relay_connections()
    finally:
        consumer_thread.join()
        while not message_queue.empty():
            message_queue.get()
            message_queue.task_done()
        message_queue.join()
        
