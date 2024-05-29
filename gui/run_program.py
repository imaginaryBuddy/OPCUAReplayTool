import sys 
from ReplayHandler import ReplayHandler
import logging 

logging.basicConfig(level=logging.DEBUG, filename="logfiles/all_logs.log", filemode="w",
                    format="%(asctime)s - %(levelname)s - %(message)s")

logger = logging.getLogger(__name__)
handler = logging.FileHandler("logfiles/run_program.log")
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)

if __name__ == "__main__":
    
    try:
        path, server_ip, computer_ip = sys.argv[1], sys.argv[2], sys.argv[3]
        looping_time_str = None
        
        snippet_start_, snippet_end_ = 0, None 

        if len(sys.argv) > 4:
            logger.debug("Length of argv > 4")
            looping_time_str = sys.argv[4]
            logger.debug(f"Looping time: {looping_time_str}")
            try:
                snippet_start_ = int(sys.argv[5])
                snippet_end_ = sys.argv[6]
                if snippet_end_ == "None":
                    snippet_end_=None
                else:
                    snippet_end_=int(snippet_end_)

                logger.debug(f"Looping enabled: {looping_time_str}, start: {snippet_start_} , end: {snippet_end_}")

            except:
                logger.exception("snippet start and end not specified properly")
                raise 
      
        RH = ReplayHandler(path, server_ip, computer_ip)
        logger.debug("RH initialized")
        RH.start()
    
        if looping_time_str:
            try:
                RH.loop(looping_time=looping_time_str, snippet_start=snippet_start_, snippet_end=snippet_end_) 
            except Exception as e:
                logger.exception("Exception")
    
        RH.disconnect() 

    except KeyboardInterrupt:
        if RH.connected:
            logger.info("RH.disconnect()")
            RH.disconnect()
        sys.exit()
    except Exception as e:
        if RH.connected:
            RH.disconnect()
        logger.debug("Exception at main")
        logger.exception(e)
        sys.exit() 
    finally:
        logger.debug("at finally clause")
        if RH and RH.connected:
            RH.disconnect()
        sys.exit() 
    # except Exception as e:
    #     print(e)
    #     print("Exception at main when ReplayHandler not initialized")
    
    # finally:
    #     print("at finally")
    #     sys.exit()
    
