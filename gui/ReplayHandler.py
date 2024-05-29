import pyshark 
from asyncua import ua
from asyncua.common import Node
from asyncua.common.subscription import Subscription
from asyncua.client import Client as AsyncClient
from asyncua.client.ua_client import UaClient
from datetime import datetime, timedelta
from asyncua.sync import Client, sync_uaclient_method, sync_async_client_method
import time 
import re 
import sys 
from itertools import islice, tee
import logging 
import signal 

# default logging file: log.log
logging.basicConfig(level=logging.DEBUG, filename="logfiles/all_logs.log", filemode="w",
                    format="%(asctime)s - %(levelname)s - %(message)s")

logger = logging.getLogger(__name__)
handler = logging.FileHandler("logfiles/ReplayHandler.log")
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)

class SubscriptionHandler:
    '''
    Based on the specifications of the opcua/ asyncua library, just search up 
    SubscriptionHandler opcua python
    '''
    def datachange_notification(self, node:Node, val, data):
        logger.debug(str(datetime.now().strftime("%Y-%m-%d %H: %M: %S %p")) + " : " + str(node) + " : " + str(val))

    def status_change_notification(self, status):
        """
        called for every status change notification from server
        """
        logger.debug("---------------------Status Change Notification--------------------")
        logger.debug(str(datetime.now().strftime("%Y-%m-%d %H: %M: %S %p")) +  " : " + str(status))

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
        self.server_ip: str  = "opc.tcp://"+server_ip+":4840"
        self.server_node: Node = None # to get the status codes later, and work on it.  
        self.client_ip: str = client_ip 
        self.client_pc: Client = None # initialized in init_server_and_client 
        self.handler: SubscriptionHandler = None 
        self.connected: bool = False # to track whether there is a connection
        self.subscription: Subscription = None # to be used when creating monitored items request 
        # TODO: these two are yet to be used for time-controlled-release of packets 
        self.first_packet_time: datetime = next((x.sniff_time for x in self.cap if "OPCUA" in str(x.layers)), None).timestamp() # get the first packet time of an opcua packet
        self.start_time: datetime = None 
        self.killed: bool = False 

    def init_server_and_client(self):
        try:
            self.client_pc = Client(self.server_ip)
            self.client_pc.connect() 
            self.server_node = self.client_pc.get_server_node() 
            self.connected = True
            logger.info("[INIT_SERVER_AND_CLIENT] Initialized Connection")
            # the following methods have to be converted to synchronous 
            # self.read_method = sync_async_client_method(AsyncClient.uaclient.read_attributes)(self.client_pc)
            # self.write_method = sync_async_client_method(AsyncClient.uaclient.write_attributes)(self.client_pc)
            self.read_method = sync_async_client_method(AsyncClient.read_values)(self.client_pc)
            self.write_method = sync_async_client_method(AsyncClient.write_values)(self.client_pc)
            
            self.update_subscription_method = sync_uaclient_method(UaClient.update_subscription)(self.client_pc)
            self.set_publishing_mode_method = sync_uaclient_method(UaClient.set_publishing_mode)(self.client_pc)
            self.set_monitoring_mode_method = sync_uaclient_method(UaClient.set_monitoring_mode)(self.client_pc)
            self.create_subscription_method = sync_async_client_method(AsyncClient.create_subscription)(self.client_pc)

        except Exception as e: 
            logger.exception(e)
            self.connected = False 
            raise 

    def disconnect(self):
        """
        Wrapped function to delete subscription, if there were any and disconnect the client-server connection
        """
        try:
            if self.subscription:
                        self.client_pc.delete_subscriptions([self.subscription.aio_obj.subscription_id])
                        # self.subscription.delete()
                        time.sleep(2)
                        logger.info("[DISCONNECT] Deleting subscription...")
                        time.sleep(2)
        except Exception as e:
            logger.exception(e)
        finally:
            logger.debug("[DISCONNECT] Client disconnecting...")
            self.client_pc.disconnect()
            time.sleep(2)
            self.client_pc.disconnect_sessionless()
            time.sleep(2)
            self.client_pc.disconnect_socket()
            time.sleep(2)
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
        except KeyboardInterrupt as e:
            logger.info("[START] Keyboard Interrupted")
            self.disconnect()
            logger.exception(e)
            raise e
        except Exception as e:
            logger.exception(e)
            raise e
        finally:
            logger.debug("[START] At finally clause")
                
                

    def loop(self, looping_time: str, snippet_start: int, snippet_end: {int, None}, starting_values: dict =None): 
        '''
        uses packets for reference to keep creating loop

        need to specify looping_time in the following format: 
        _W;_D;_H;_M;_S; 
        Weeks, Days, Hours, Minutes, Seconds

        TODO: starting_values has to be given in a dictionary format, 
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
            e = ValueError("Need to specify how long to loop")
            logger.exception(e)
            raise e
        if not isinstance(looping_time, str):
            e = TypeError("looping_time has to be a string")
            logger.exception(e)
            raise e
        
        digit_re = r"[\d*\.]?\d+[WDHMS]"
        if not re.match(digit_re, looping_time):
            e = ValueError("looping_time has to follow the regex '[\\d*\\.]?\\d+[WDHMS]'")
            logger.exception(e)
            raise e

        timings = re.findall(r'[\d*\.]?\d+', looping_time)
        
        future_time = datetime.now() + timedelta(weeks=int(timings[0]), days=int(timings[1]), hours=int(timings[2]), minutes=int(timings[3]), seconds=int(timings[4]))
        
        # TODO: allow starting_values 
    
        try:
            self.process_packets(snippet_start, snippet_end, future_time, description="LOOP_PROCESS_PACKETS", loop=True)

        except KeyboardInterrupt:
            logger.error("[LOOP] Keyboard Interrupt")
            self.disconnect()
            logger.info("[LOOP] Exiting program")
            raise

        except Exception as e:
            logger.error("[LOOP] Exception occurred")
            logger.exception(e)
            raise 

        finally:
            self.disconnect() 
            logger.info("[LOOP] System Exiting")
            sys.exit() 
    
   
    def process_packets(self, start: int, end: int, future_time, description="PROCESS_PACKETS", loop=False):
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
            while datetime.now() < future_time:
                logger.debug(f"[{description}] Start Processing Sequence of Packets")
                cap_sliced, cap_sliced_reset = tee(cap_sliced, 2)
                i = start
                try:
                    for packet in cap_sliced_reset:
                        i += 1 
                        try:
                            if datetime.now() > future_time:
                                self.disconnect()
                                time.sleep(4)
                                sys.exit()
                            # only deal with MSG types
                            if "OPCUA" in str(packet.layers) and packet['OPCUA'].get_field_value('transport_type') == "MSG":
                                service_node_id = packet['OPCUA'].get_field_value('servicenodeid_numeric')
                                if service_node_id == '631': # Read Request 
                                    all_relevant = self._get_nodes_info_read(packet)
                                    # all_relevant_nodes = [map(lambda x: self.client_pc.get_node(x), all_relevant)]
                                    # self.client_pc.uaclient.get_attributes(all_relevant, ua.AttributeIds.Value)
                                    
                                    self.read_method(all_relevant)
                                    # self.read_method(nodeids=all_relevant, attr=ua.AttributeIds.Value)
                                    # self.client_pc.read_values(nodes=all_relevant)
                                    # client_pc.get_values(all_relevant)
                                    logger.debug(f"[{description}] Read Request")

                                elif service_node_id == '673': # Write Request 
                                    logger.debug(f"[{description}] Write Request")
                                    all_relevant, write_value = self._get_nodes_info_write(packet)
                                    # all_relevant_nodes = [map(lambda x: self.client_pc.get_node(x), all_relevant)]
                                    # write_value = [ua_utils.value_to_datavalue(write_value)]
                                    # print(write_value)
                                    # print(type(write_value))
                                    write_value = [ua.DataValue(ua.Variant(int(write_value), ua.VariantType.Int16))] # TODO: FIXING THIS TO BE INT, BUT IT'S A temporary fix
                                    # self.client_pc.uaclient.set_attributes(all_relevant, write_value, ua.AttributeIds.Value)
                                    # self.client_pc.write_values(nodes=all_relevant, values=write_value)
                                    # self.write_method(nodeids=all_relevant, datavalues=write_value, attributeid=ua.AttributeIds.Value)
                                    self.write_method(all_relevant, values=write_value)
                                    time.sleep(1)

                                elif service_node_id == '787': # Create Subscription Request
                                    print(f"[{description}] Create Subscription Request")
                                    self.sub_packet = packet 

                                elif service_node_id == '751': # Create Monitored Items Request
                                    '''
                                    Note: there is an assumption that I made here, which is that CreateMonitoredRequest comes
                                    immediately after CreateSubscriptionRequest
                                    '''
                                    logger.debug(f"[{description}] Create Monitored Items Request: {i}")
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
                                    
                                    self.subscription = self.create_subscription_method(period=params, handler=self.handler)
                                    time.sleep(1.0)
                                    logger.debug(f"[{description}] subscription_id: {self.subscription.aio_obj.subscription_id}")
                                    time.sleep(0.5)                            
                                    obj_to_subscribe = self._get_nodes_info_subscribe(packet)
                                    logger.debug(f"[{description}] obj_to_subscribe: {obj_to_subscribe}")
                                    nodes = list(map(lambda x: self.client_pc.get_node(x), obj_to_subscribe))
                                    logger.debug(f"[{description}] nodes to subscribe: {nodes}")
                                    self.handle = self.subscription.subscribe_data_change(nodes)

                                    logger.info(f"[{description}] Create Monitored Items Parameters")
                                    logger.info(f"Max keep alive count: {params.RequestedMaxKeepAliveCount}")
                                    logger.info(f"Publishing interval: {params.RequestedPublishingInterval}")
                                    logger.info(f"Priority: {params.Priority}")
                                    logger.info(f"Max notifications {params.MaxNotificationsPerPublish}")
                                    logger.info("------------------------------------------------------------")
                                elif service_node_id == "793": # modify subscription request 
                                    # print(f"[{description}] modify subscription request")
                                    logger.debug(f"[{description}] modify subscription request")
                                    # TODO: limitation of the opcua python library now, unable to modify the subscription, unless deleting and resubscribing 
                                    # check that sub exists 
                                    if not self.subscription:
                                        e = ValueError(f"[{description}] Subscription doesn't exist")
                                        logger.exception(e)
                                        raise e 
                                    if not self.handle: 
                                        e = ValueError(f"[{description}] Handle doesn't exist")
                                        logger.exception(e)
                                        raise e 
                                    else: 
                                        params = ua.ModifySubscriptionParameters()
                                        params.SubscriptionId = int(self.subscription.aio_obj.subscription_id)
                                        params.MaxNotificationsPerPublish = int(packet.OPCUA.MaxNotificationsPerPublish)
                                        params.RequestedPublishingInterval = int(packet.OPCUA.RequestedPublishingInterval)
                                        params.RequestedMaxKeepAliveCount = int(packet.OPCUA.RequestedMaxKeepAliveCount)
                                        params.Priority = int(packet.OPCUA.Priority)
                                        params.RequestedLifetimeCount = int(packet.OPCUA.RequestedLifetimeCount)
                                        self.update_subscription_method(params)

                                elif service_node_id == "799": # set publishing mode 
                                    # print(f"[{description}] set publishing mode request")
                                    logger.debug(f"[{description}] set publishing mode request")
                                    if not self.subscription:
                                        e = ValueError(f"[{description}] Subscription doesn't exist")
                                        logger.exception(e)
                                        raise e
                                    if not self.handle: 
                                        e = ValueError(f"[{description}] Handle doesn't exist")
                                        logger.exception(e) 
                                        raise e 
                                    else: 
                                        params = ua.SetPublishingModeParameters()
                                        params.SubscriptionIds = [int(self.subscription.aio_obj.subscription_id)] # by right this should be a list of subscription ids! 
                                        params.PublishingEnabled = True if packet.OPCUA.PublishingEnabled == "True" else False 
                                        self.set_publishing_mode_method(params)
            
                                elif service_node_id == "769": # set monitoring mode request
                                    # print(f"[{description}] set monitoring mode request")
                                    logger.debug(f"[{description}] set monitoring mode request")
                                    if not self.subscription:
                                        raise ValueError(f"[{description}] Subscription doesn't exist")
                                    if not self.handle: 
                                        raise ValueError(f"[{description}] Handle doesn't exist")
                                    else: 
                                        params = ua.SetMonitoringModeParameters()
                                        params.SubscriptionId = int(self.subscription.aio_obj.subscription_id)
                                        params.MonitoringMode = ua.MonitoringMode(int(packet.OPCUA.MonitoringMode, 0)) # this "guesses" the base of the string. so MonitoringMode itself returns 0x000002 as string, and you just convert to int)
                                        params.MonitoredItemIds = list(map(lambda x: int(x.get_default_value()), packet.OPCUA.MonitoredItemIds.all_fields))
                                        self.set_monitoring_mode_method(params)
                                        # print(params.MonitoredItemIds)

                                time.sleep(1)

                            else:
                                # print("Not a relevant packet")
                                pass                            
                        except Exception as e:
                            logger.exception(f"[{description}] Exception Encountered for packet of index {start}")
                            raise
                    
                    if not loop:
                        break   

                except (ua.UaError, ua.uatypes.UaStatusCodeError, ua.uaerrors._auto.BadTooManyPublishRequests)as e:
                    #TODO: unfortunately, I still haven't been able to catch this error
                    logger.exception("#TODO: catch uaerror")
                    time.sleep(5)
                    self.init_server_and_client()    
                    self.start_time = datetime.now().timestamp()

                except KeyboardInterrupt: 
                    logger.exception(f"[{description}] Keyboard interrupted")
                    self.disconnect()
                    raise

                except Exception as e:
                    logger.exception(f"[{description}] Handling Exception...")
                    raise 
        
        except Exception as e:
            logger.exception(e)

        finally: 
            logger.debug(f"[{description}] at finally clause")
                            

    def _get_nodes(self, packet):
        '''
        returns the nodes of the  packet, based on the node namespaces and ids specified in the packet 
        '''
        identifier_type = tuple(map(lambda x: x.get_default_value(), packet.OPCUA.nodeid_encodingmask.all_fields))
        logger.debug("_get_nodes")
       
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

        logger.debug(f"len(nodeids_numeric): {len(nodeids_numeric)}")
        logger.debug(f"len(nodeids_string): {len(nodeids_string)}")
        logger.debug(f"len(nodeids_guid): {len(nodeids_guid)}")
        total_nodeids_num = len(nodeids_numeric) + len(nodeids_string) + len(nodeids_guid)
        # TODO: deal with nodeids_bytes as well 

        namespaces = list(map(lambda x: x.get_default_value(), packet.OPCUA.nodeid_nsindex.all_fields))[1:]
        logger.debug(f"namespaces: {namespaces} ")
        all_relevant_nodes = []
        logger.debug(f"len(identifier_type[2:]): {len(identifier_type[2:])}")
        if len(identifier_type[2:]) != len(namespaces): 
            logger.debug(f"len(identifier_type) != len(namespaces)")
            identifier_type = [identifier_type[i] for i in range(0, len(identifier_type[2:]), 2)]
            logger.debug(f"identifier_type: {identifier_type}")
        else:
            logger.debug("len(identifier_type) == len(namespaces)")
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
        except Exception as e:
            logger.debug("---------Exception occurred---------")
            logger.debug(f"This is the namespaces {namespaces}")
            logger.debug(f"this is identifier_type {identifier_type}")
            logger.exception(e)
            raise

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
        logger.debug("_get_nodes_info_read")
        try:
            nodeids = self._get_nodes(packet)
            nodes = list(map(lambda x: self.client_pc.get_node(x), nodeids))
            return nodes
        except:
            raise
    
    def _get_nodes_info_write(self, packet):
        logger.debug("_get_nodes_info_write")
        try:
            # all_relevant_nodes = self._get_nodes(packet)
            nodeids = self._get_nodes(packet)
            nodes = list(map(lambda x: self.client_pc.get_node(x), nodeids))
            # TODO: figure out the type of datatype, for now, just default to Int16
            # variant_encoding_mask = packet.OPCUA.Value
            write_values = packet.OPCUA.int16.get_default_value()
            return nodes, write_values 
        except:
            raise

    def _get_nodes_info_subscribe(self, packet):
        try:
            logger.debug("_get_nodes_info_subscribe")
            return self._get_nodes(packet)
        except:
            raise
    
    def _get_nodes_info_monitor(self, packet):
        try:
            logger.debug("_get_nodes_info_monitor")
            nodeids = list(map(lambda x: x.get_default_value(), packet.OPCUA.monitored_item_ids.all_fields()))
            return nodeids 
        except:
            raise
        
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
    
    """
    To handle SIGINT and SIGTERM
    Reference: https://stackoverflow.com/questions/18499497/how-to-process-sigterm-signal-gracefully
    #TODO: Verify that this works if SIGINT or SIGTERM encountered
    """

    def _handler(self, signum, frame):
        logging.error("Received SIGINT or SIGTERM! Finishing this block, then exiting.")
        self.killed = True

    def __enter__(self):
        self.old_sigint = signal.signal(signal.SIGINT, self._handler)
        self.old_sigterm = signal.signal(signal.SIGTERM, self._handler)
        # self.old_sigkill = signal.signal(signal.SIGKILL, self._handler)
        return self

    def __exit__(self, type, value, traceback):
        if self.killed:
            logger.debug("__exit__ disconnecting")
            self.disconnect()
            sys.exit(0)
        signal.signal(signal.SIGINT, self.old_sigint)
        signal.signal(signal.SIGTERM, self.old_sigterm)
        # signal.signal(signal.SIGKILL, self.old_sigkill)