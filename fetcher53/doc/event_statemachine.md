# Basic structure
- delegation point
  zone and all its name servers
- event
  a single query and with start and finish state 
  may created by end user or generated as subevent 
  root prime and missing glue will generate subevent for original event

# StateMachine 
```text
   +--------------------------------------------------------------------------+
   |                                                                          |
   |               +----------------------+                                   |
   |               |                      |                                   |
+--v---+    +------v-------+      +-------+--------+          +----------+    |
| init |--->| query target |----->| query response |--------->| finished |    |
+--+---+    +--------------+      +----------------+          +----------+    |
   |                                                                          |
   |                                                                          |
   |        +--------------+      +----------------+       +----------------+ |
   +------->| query target |----->| query response |------>| prime response |-+
            +--------------+      +----------------+       +----------------+



//missing glue
+--------------+
| query target |<-------------------------------------------------------------+
+-----+--------+                                                              |
      |                                                                       |
      |                                                                       |
      |        +------+        +------------+        +-----------------+      |
      +------->| init |------->|  ........  |------->| target response |------+
               +------+        +------------+        +-----------------+
```
## Normal query
- Search cache 
- Get dp from cache, into query target state
- Get Response
  - Get answer then go to finish and send back response to end user
  - Get referral, create new dp from the answer and go back to query target
  - Get cname, reset current query (backup original query) and go back to init
  
# Cold cache 
- Create subevent, Get dp from root hint, into query target state
- Get Respone, Create dp from answer, and let orginal event into query target state

# Missing glue
- When at query target state, and there is no glue find in dp, usually it's caused
  by out of zone glue
- Create subevent with the missing glue and set its state to init and finish state 
  to target response
- When state translate from query response to target response, it will update the 
  original event's dp, and resume the original event 
