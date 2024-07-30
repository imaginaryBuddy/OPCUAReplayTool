# Network-Analysis-Tool
This tool aims to replay OPCUA packets by simulating the sequence of events from a Wireshark capture 

## Motivation 
When customers raise issues, it is hard to replay the same process that caused an issue like a PLC crash for example. Therefore, this python script aims to take in a Wireshark capture, along with a PLC that already has the application that caused the issue downloaded, and simulate the whole process through 
1. Creating an OPCUA client and making a successful connection 
2. Then, follow the sequence of wireshark capture opcua packets and their request parameters to send to the PLC.  

## Dependencies 
```
asyncua (for replay_asyncua) (V1.1.0)
opcua (for the deprecated version) (V0.98.13)
pyshark (V0.6)
datetime 
time
re
itertools
```

## Important, before you start 
1. In order to make the `asyncua` library work for our use case, please "disable" the watchdog which will keepAlive by sending Read Requests constantly. 
To "disable", go to the asyncua library source code in your local machine, 
`import math` and initialize `asyncua.client.Client` class's `self.watchdog_intervall = math.inf`, this will cause the keepAlive to send read requests every interval of infinite seconds. 

A shortcut to this step is to write `import asyncua.client.Client` then ctrl + click onto that, then you'll be able to view the source codes. 

2. Ensure that the application to debug is INSTALLED into the PLC using ESME, in order to simulate the same scenario in the PLC. 

## Usage 
### replay_asyncua.py 
I would recommend using this program as it uses asyncua, and has more "functionalities" like different packet cases as compared to deprecated_version.py

I have used the synchronous version of this library as it makes things more straightforward. 

1. Initialize a ReplayHandler 
```python
        RH = ReplayHandler("<PATH TO WIRESHARK CAPTURE>", "opc.tcp://<IP address of PLC>", None)
        time.sleep(2)

```
2. Start the replay 
```python
        RH.start() # start the replay from start to finish of the whole wireshark capture
```
3. Loop 
```python
        RH.loop(looping_time="0W;0D;0H;30M;0S;", snippet_start=31, snippet_end=None) 
        # looping time must be specified in a specific format, go to the function definition to read on how 
        # snippet_start is the start of the loop, meaning which packet do you want to start your loop with 
        # snippet_end None means till the end, otherwise, it specifies the packet that it ends with (inclusive!)
```
4. Disconnect 
```python
        RH.disconnect() # handles deletion of subscription and disconnection with PLC 
```
### deprecated_version.py
There are some packets that cannot be simulated using the deprecated `opcua` library, for example: 
- ModifySubscriptionRequest 
- SetPublishingMode 

Publish Responses to Publish Requests from the `opcua` library, will cause some sort of BadSequenceNumberUnknown ua error, that's why `asyncua` is better, as it fixes this bug

Also, there isn't any community support for this library. 

The way to call the functions is similar to the one in replay_asyncua.py

## Additional Information
There was prior research and failures before this project. To read more about how it led to the current method of replaying, it's on the confluence blog. :) 

## Limitations 
1. The time release control is yet to be implemented, meaning, each packet, is released at a set timing instead of following the time from the Wireshark capture 
2. Might be met with BadTooManySubscriptions ua exception, more needs to be researched into to amend this. Maybe add a check to see whether objects have already been subscribed.
   
![Screenshot 2024-07-30 at 12 05 46 PM](https://github.com/user-attachments/assets/a87e12a1-db19-4a1e-b9a7-0c59ce117e8c)



