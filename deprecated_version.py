import pyshark 
from opcua.client.client import *
from opcua.client.ua_client import *
from opcua import ua 
from datetime import datetime, timedelta
import time 
import re 
import sys 
from itertools import islice 

logging.basicConfig(level=logging.DEBUG, filename="logfiles/all_logs.log", filemode="w",
                    format="%(asctime)s - %(levelname)s - %(message)s")

logger = logging.getLogger(__name__)
handler = logging.FileHandler("logfiles/deprecated_version.log")
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)

class SubscriptionHandler:
    '''
    Based on the specifications of the opcua/ asyncua library, just search up 
    SubscriptionHandler opcua python
    '''
    def datachange_notification(self, node:Node, val, data):
        print(str(datetime.now().strftime("%Y-%m-%d %H: %M: %S %p")) + " : " + str(node) + " : " + str(val))
    
    def status_change_notification(self, status):
        """
        called for every status change notification from server
        """
        print("---------------------Status Change Notification--------------------")
        print(str(datetime.now().strftime("%Y-%m-%d %H: %M: %S %p")) +  " : " + str(status))

class ReplayHandler:
    def __init__(self, fileCapture, server_ip, client_ip):
        """
        Initialization of ReplayHandler

        ReplayHandler wraps all the functions and data structures required to replay a pcap file for OPCUA protocol. 

        Parameters
        ----------
        fileCapture : str
            The path of the pcap file to replay 
        server_ip : str
            The ip address of the server (e.g: the PLC server)
        client_ip: str
            The ip address of the client (e.g: the computer)

        Returns
        -------
        None
        """
        self.fileCapture: str = fileCapture 
        self.cap: pyshark.FileCapture = pyshark.FileCapture(fileCapture) # assume that the capture is already OPCUA filtered 
        self.server_ip: str  = server_ip 
        self.server_node: Node = None # to get the status codes later, and work on it.  
        self.client_ip: str = client_ip 
        self.client_pc: Client = None # initialized in init_server_and_client 
        self.handler: SubscriptionHandler = None 
        self.connected: bool = False # to track whether there is a connection
        self.subscription: Subscription = None # to be used when creating monitored items request 
        # TODO: these two are yet to be used for time-controlled-release of packets 
        self.first_packet_time: datetime = next((x.sniff_time for x in self.cap if "OPCUA" in str(x.layers)), None).timestamp() # get the first packet time of an opcua packet
        self.start_time: datetime = None 


    def init_server_and_client(self):
        try:
            self.client_pc = Client(self.server_ip)
            self.client_pc.connect() 
            self.server_node = self.client_pc.get_server_node() 
            self.connected = True
            print("Initialized Connection")
        except Exception as e: 
            print(e)
            self.connected = False 
            raise 

    def disconnect(self):
        """
        Wrapped function to delete subscription, if there were any and disconnect the client-server connection
        """
        if self.subscription:
                    self.subscription.delete()
                    print("[DISCONNECT] Deleting subscription...")
                    time.sleep(2)
        print("[DISCONNECT] Client disconnecting...")
        self.client_pc.disconnect()
        self.connected = False

    def start(self):
        """
        Follows the sequence of the fileCapture

        Note: make sure to manually disconnect the client-server connection yourself. 
        start will start by initializing the server-client connection, and process packets until the end of the pcap capture. 

        To stop this process, use KeyboardInterrupt

        Parameters
        ----------
        loop_or_not : str

        Returns
        -------
        None
        """
        self.init_server_and_client() 
        self.start_time = datetime.now().timestamp() 

        try:
           self.process_packets(start=0, end=None, future_time=None, description="START_PROCESS_PACKETS")
        except KeyboardInterrupt:
            print("[START] Keyboard Interrupted")
            raise
        except Exception as e:
            print(e)
            raise
        finally:
            print("[START] At finally clause")
                
                

    def loop(self, looping_time: str, snippet_start: int, snippet_end: {int, None}, starting_values: dict =None): 
        '''
        uses packets for reference to keep creating loop

        need to specify looping_time in the following format: 
        _W;_D;_H;_M;_S; 
        Weeks, Days, Hours, Minutes, Seconds

        starting_values has to be given in a dictionary format, 
        {
            [namespace1]_[node_id1] = [starting_value1], 
            [namespace2]_[node_id2] = [starting_value2],
            [namespace3]_[node_id3] = [starting_value3],
            ...
            [namespaceN]_[node_idN] = [starting_valueN]
        }

        Parameters
        ----------
        looping_time : str  
            How long to execute the loop. 
            In this format _W;_D;_H;_M;_S;, where _ represents an integer 

        snippet_start : int
            The start index of 

        TODO: Haven't implemented the logic for using starting_values 
        starting_values: str 
            Default None. Must be specified in a dictionary form stated in the description of this function 
            Specifies for the node, what values the loop should start using 

        Returns
        -------
        None
        '''
        if looping_time == None:
            raise ValueError("Need to specify how long to loop")
        if not isinstance(looping_time, str):
            raise TypeError("looping_time has to be a string")
        digit_re = r"[\d*\.]?\d+[WDHMS]"
        if not re.match(digit_re, looping_time):
            raise ValueError("looping_time has to follow the regex '[\\d*\\.]?\\d+[WDHMS]'")
        
        timings = re.findall(r'[\d*\.]?\d+', looping_time)
        print(timings)
        
        future_time = datetime.now() + timedelta(weeks=int(timings[0]), days=int(timings[1]), hours=int(timings[2]), minutes=int(timings[3]), seconds=int(timings[4]))
        
        # TODO: allow starting_values 
    
        try:
            self.process_packets(snippet_start, snippet_end, future_time, description="LOOP_PROCESS_PACKETS")
    # while(datetime.now() < future_time):
    #     self.start_time = time.now() 
    #     self.first_packet_time = packets_for_reference[0].sniff_time 
    #     self._process_packets(packets_for_reference)
        except KeyboardInterrupt:
            print("[LOOP] Keyboard Interrupt")
            print("[LOOP] Exiting program")
            raise
            # self.disconnect() 
            # sys.exit() 
        finally:
            print("[LOOP] Exception occurred")
            self.disconnect() 
            print("[LOOP] System Exiting")
            sys.exit() 
    
   
    def process_packets(self, start: int, end: int, future_time, description="PROCESS_PACKETS"):
        """
        start: int
            the start index of the start packet in the capture file (inclusive)
        end: int 
            the end index of the end packet in the capture file (incusive)
            put None, if you want it to iterate till the end of the capture
        future_time: datetime 
            the time to end the processing  

        Note that self.cap is an iterator, so u cannot use len(iterator) to get the "length" of it, we have to use itertools.islice 
        """
        i = start # to keep track of the last executed packet 
        if not future_time:
            future_time = datetime.max

        if not end:
            cap_sliced = islice(self.cap, start, None) 
        else:
            cap_sliced = islice(self.cap, start, end+1)

        try:
            for packet in cap_sliced:
                i += 1 
                try:
                    if datetime.now() > future_time:
                        break
                    # only deal with MSG types
                    if "OPCUA" in str(packet.layers) and packet['OPCUA'].get_field_value('transport_type') == "MSG":
                        service_node_id = packet['OPCUA'].get_field_value('servicenodeid_numeric')
                        if service_node_id == '631': # Read Request 
                            all_relevant = self._get_nodes_info_read(packet)
                            self.client_pc.uaclient.get_attributes(all_relevant, ua.AttributeIds.Value)
                            print(f"[{description}] Read Request")
                        elif service_node_id == '673': # Write Request 
                            print(f"[{description}] Write Request")
                            all_relevant, write_value = self._get_nodes_info_write(packet)
                            print(write_value)
                            print(type(write_value))
                            write_value = [ua.DataValue(ua.Variant(int(write_value), ua.VariantType.Int16))] # TODO: FIXING THIS TO BE INT, BUT IT'S A temporary fix
                            self.client_pc.uaclient.set_attributes(all_relevant, write_value, ua.AttributeIds.Value)
                            time.sleep(1)
                        elif service_node_id == '787': # Create Subscription Request
                            print(f"[{description}] Create Subscription Request")
                            self.sub_packet = packet 

                        elif service_node_id == '751': # Create Monitored Items Request
                            '''
                            Note: there is an assumption that I made here, which is that CreateMonitoredRequest comes
                            immediately after CreateSubscriptionRequest
                            '''
                            print(f"[{description}] Create Monitored Items Request: ", i)
                            if not self.handler: 
                                self.handler = SubscriptionHandler() 
    
                            # need to use the subscription packet parameters, not the current one, because the current packet would be Create Monitored Items Request
                            params = ua.CreateSubscriptionParameters()
                            params.RequestedPublishingInterval = int(self.sub_packet.OPCUA.RequestedPublishingInterval)
                            params.RequestedLifetimeCount = int(self.sub_packet.OPCUA.RequestedLifetimeCount)
                            params.RequestedMaxKeepAliveCount = int(self.sub_packet.OPCUA.RequestedMaxKeepAliveCount)
                            params.PublishingEnabled = True if self.sub_packet.OPCUA.PublishingEnabled == "True" else False
                            params.Priority = 0
                            params.MaxNotificationsPerPublish = int(self.sub_packet.OPCUA.MaxNotificationsPerPublish)
                            
                            self.subscription = self.client_pc.create_subscription(period=params, handler=self.handler)
                            time.sleep(0.5)                            
                            obj_to_subscribe = self._get_nodes_info_subscribe(packet)
                            nodes = list(map(lambda x: self.client_pc.get_node(x), obj_to_subscribe))
                            self.handle = self.subscription.subscribe_data_change(nodes)

                            print("max keep alive count: ", params.RequestedMaxKeepAliveCount)
                            print("pubishing interval: ", params.RequestedPublishingInterval)
                            print("priority: ", params.Priority)
                            print("max notifications ", params.MaxNotificationsPerPublish)

                        elif service_node_id == "793": # modify subscription request 
                            print(f"[{description}] modify subscription request")
                            # TODO: limitation of the opcua python library now, unable to modify the subscription, unless deleting and resubscribing 
                            # check that sub exists 
                            if not self.subscription:
                                raise ValueError("Subscription doesn't exist")
                            if not self.handle: 
                                raise ValueError("Handle doesn't exist")
                            else: 
                                pass
                                # sub.modify_monitored_item(handle)
                        # self._wait_for_packet_time(packet.sniff_time.timestamp())
                        time.sleep(1)
                    else:
                        print("Not a relevant packet")
                    
                except Exception as e:
                    print(e)
                    print(f"[{description}] Exception Encountered")
                    raise
                
        except (ua.UaError, ua.uatypes.UaStatusCodeError, ua.uaerrors._auto.BadTooManyPublishRequests)as e:
            #TODO: unfortunately, I still haven't been able to catch this error 
            print(e) 
            time.sleep(5)
            self.init_server_and_client()    
            self.start_time = datetime.now().timestamp()

        except KeyboardInterrupt: 
            print(f"[{description}] Keyboard interrupted")
            raise

        except Exception as e:
            print(f"[{description}] Handling Exception...")
            print(e)
            raise 
    
        finally: 
            print(f"[{description}] Returning i to caller")
            return i 
                        

    def _get_nodes(self, packet):
        '''
        returns the nodes of the  packet, based on the node namespaces and ids specified in the packet 
        '''
        identifier_type = tuple(map(lambda x: x.get_default_value(), packet.OPCUA.nodeid_encodingmask.all_fields))

        total_nodeids_num = 0 
        try:
            nodeids_numeric = list(map(lambda x: x.get_default_value(), packet.OPCUA.nodeid_numeric.all_fields))[2:] # here I am assuming that the first 2 nodes are the session id (some number) and the root node (0), so i dont include them
        except:
            nodeids_numeric = []  
        try: 
            nodeids_string = list(map(lambda x: x.get_default_value(), packet.OPCUA.nodeid_string.all_fields))
        except: 
            nodeids_string = [] 
        try:
            nodeids_guid = list(map(lambda x: x.get_default_value(), packet.OPCUA.nodeid_guid.all_fields))
        except:
            nodeids_guid = []

        print("len(nodeids_numeric): ", len(nodeids_numeric))
        print("len(nodeids_string): ", len(nodeids_string))
        print("len(nodeids_guid): ", len(nodeids_guid))
        total_nodeids_num = len(nodeids_numeric) + len(nodeids_string) + len(nodeids_guid)
        # TODO: deal with nodeids_bytes as well 

        namespaces = list(map(lambda x: x.get_default_value(), packet.OPCUA.nodeid_nsindex.all_fields))[1:]
        all_relevant_nodes = []
        print("len(identifier_type[2:]): ", len(identifier_type[2:]))
        if len(identifier_type[2:]) != total_nodeids_num: 
            
            print("len(identifier_type) != total_nodeids_num")
            identifier_type = [identifier_type[i] for i in range(0, len(identifier_type[2:]), 2)]
            print("identifier_type: ", identifier_type)
        else:
            identifier_type = identifier_type[2:]
        try:
            for type in identifier_type: 
                '''
                According to this specification: https://reference.opcfoundation.org/Core/Part6/v104/docs/5.2.2#:~:text=Table%206%20%E2%80%93%20NodeId%20DataEncoding%20values
                Creating nodes based on this specification: https://opcua-asyncio.readthedocs.io/en/latest/usage/common/node-nodeid.html 
                '''
                if type in ["0x00", "0x01", "0x02"]: # node id in numeric/ byte form NOTE: unsure whether the byte form will be the same as in numeric form, see https://opcua-asyncio.readthedocs.io/en/latest/usage/common/node-nodeid.html#:~:text=of%20the%20NodeId-,i%2C%20s%2C%20g%2C%20b,-These%20keys%20will , there seems to be a way to declare byte-identified nodes 
                    all_relevant_nodes.append(ua.NodeId.from_string(f'ns={namespaces.pop(0)};i={nodeids_numeric.pop(0)}'))
                elif type == "0x03": # node id encoded in string format 
                    all_relevant_nodes.append(ua.NodeId.from_string(f'ns={namespaces.pop(0)};s={nodeids_string.pop(0)}'))
                elif type == "0x04": # node id encoded in guid 
                    all_relevant_nodes.append(ua.NodeId.from_string(f'ns={namespaces.pop(0)};g={nodeids_guid.pop(0)}'))
                else:
                    print("The nodeid identifier type is invalid")
        except:
            print("Exception occurred")
            print("this is the namespace", namespaces)
            print("this is identifier_type", identifier_type)
        return all_relevant_nodes
        

    '''
    the "nodes info" returned by the following functions will have different definitions based 
    on the type of operation to perform. 
    
    For example, for _get_nodes_info_write, I want to return the nodes (ua.NodeId type)
    and their respective write values. 

    For _get_nodes_info_monitor, I want to get the nodeids as a list of strings, so it's really
    up to how you want to define the return object! Feel free to make amendments if needed 

    '''
    def _get_nodes_info_read(self, packet):
        return self._get_nodes(packet)
    
    def _get_nodes_info_write(self, packet):
        all_relevant_nodes = self._get_nodes(packet)
        # TODO: figure out the type of datatype, for now, just default to Int16
        # variant_encoding_mask = packet.OPCUA.Value
        write_values = packet.OPCUA.int16.get_default_value()
        return all_relevant_nodes, write_values 

    def _get_nodes_info_subscribe(self, packet):
        return self._get_nodes(packet)
    
    def _get_nodes_info_monitor(self, packet):
        nodeids = list(map(lambda x: x.get_default_value(), packet.OPCUA.monitored_item_ids.all_fields()))
        return nodeids 
    
    """
    time release control 
    I have yet to use this, but you can try, for now, im just using timeout 
    """
    def _wait_for_packet_time(self,packet_time):
        current_time=datetime.now().timestamp() #recover current time
        
        if current_time-self.start_time < float(packet_time-self.first_packet_time): # if it's not yet time to send the packet
            time_to_wait=float(packet_time-self.first_packet_time)-(current_time-self.start_time) #calculate the time to wait
            time.sleep(time_to_wait) #sleep until it's time to send the packet
        else:
            print("sending packet with delay of {} s".format(float(packet_time-self.first_packet_time)- (current_time-self.start_time)))
        return

if __name__ == "__main__":
    try:
        RH = ReplayHandler("C:/opcua_tool_shenhwei/pcap_captures/xingyu_opcua_packets.pcap", "opc.tcp://192.168.1.30:4840", None)
        time.sleep(2)
        RH.start()
        RH.loop(looping_time="0W;0D;0H;30M;0S;", snippet_start=31, snippet_end=None) 
        RH.disconnect() 
    except KeyboardInterrupt:
        if RH.connected:
            RH.disconnect()
        sys.exit()
    except Exception as e:
        if RH.connected:
            RH.disconnect()
        print("Exception at main")
        print(e)
        sys.exit() 
    finally:
        if RH.connected:
            RH.disconnect()
        sys.exit() 
    
    
