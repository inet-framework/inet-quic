Example: Request/Response-Based Communication
=============================================

This step contains a simplified version of a client/server and a request/response-based
communication. The client initiates the communication by sending a request to the server.
The server processes requests in the order of arrival and generates the response traffic.

Request packets are produced periodically and randomly by an active packet
source (:ned:`ActivePacketSource`) in the client. The generated requests fall into one of
two categories based on the data they contain.

The server processes requests one by one in order, using a compound consumer
(:ned:`RequestConsumer`). Each request is first classified based on the data it contains,
and then a certain number of tokens are generated as the request is consumed.

The tokens are added to a response server in a compound producer (:ned:`ResponseProducer`).
The response producer generates different traffic randomly over a period of time
for each kind of request.

The client consumes the response packets by a passive packet sink (:ned:`PassivePacketSink`).

.. figure:: media/ResponseProducer.png
   :align: center

.. figure:: media/RequestResponse.png
   :align: center
   :width: 40%

.. figure:: media/RequestConsumer.png
   :align: center

.. literalinclude:: ../QueueingTutorial.ned
   :start-at: network RequestResponseTutorialStep
   :end-before: //----
   :language: ned

.. literalinclude:: ../omnetpp.ini
   :start-at: Config RequestResponse
   :end-at: provider[1].providingInterval
   :language: ini
