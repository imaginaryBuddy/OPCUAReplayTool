import time 
import sys 
import logging 
from gui.ReplayHandler import ReplayHandler, SubscriptionHandler


logging.basicConfig(level=logging.DEBUG, filename="logfiles/all_logs.log", filemode="w",
                    format="%(asctime)s - %(levelname)s - %(message)s")

logger = logging.getLogger(__name__)
handler = logging.FileHandler("logfiles/replay_asyncua.log")
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)

if __name__ == "__main__":
    try:
        RH = ReplayHandler("C:/opcua_tool_shenhwei/pcap_captures/short_test_2.pcap", "192.168.1.30", None)
        logger.debug("RH Initialized")
        time.sleep(2)
        RH.start()
        logger.debug("RH.start() completed")
        logger.debug("Entering RH.loop()")
        RH.loop(looping_time="0W;0D;0H;2M;0S;", snippet_start=8, snippet_end=None) 
        RH.disconnect() 
        
    except KeyboardInterrupt:
        if RH.connected:
            RH.disconnect()
        sys.exit()
    except Exception as e:
        if RH.connected:
            RH.disconnect()
        # print("Exception at main")
        # print(e)
        logger.exception("Exception")
        sys.exit() 
    finally:
        if RH.connected:
            RH.disconnect()
        sys.exit() 
    
    
