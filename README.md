## Data Trading Platform

A sample Node.js app to demonstrate **__fabric-client__** & **__fabric-ca-client__** Node.js SDK APIs

### Prerequisites and setup:

* [Docker](https://www.docker.com/products/overview) - v1.12 or higher
* [Docker Compose](https://docs.docker.com/compose/overview/) - v1.8 or higher
* [Git client](https://git-scm.com/downloads) - needed for clone commands
* **Node.js** v6.9.0 - 6.10.0 ( __Node v7+ is not supported__ )
* [Download Docker images](http://hyperledger-fabric.readthedocs.io/en/latest/samples.html#binaries)

```
cd Data-Trading-Platform/
```

Once you have completed the above setup, you will have provisioned a local network with the following docker container configuration:

* 2 CAs
* A SOLO orderer
* 4 peers (2 peers per Org)
* 4 couchdb (1 couchdb per peer)

#### Artifacts
* Crypto material has been generated using the **cryptogen** tool from Hyperledger Fabric and mounted to all peers, the orderering node and CA containers. More details regarding the cryptogen tool are available [here](http://hyperledger-fabric.readthedocs.io/en/latest/build_network.html#crypto-generator).
* An Orderer genesis block (genesis.block) and channel configuration transaction (mychannel.tx) has been pre generated using the **configtxgen** tool from Hyperledger Fabric and placed within the artifacts folder. More details regarding the configtxgen tool are available [here](http://hyperledger-fabric.readthedocs.io/en/latest/build_network.html#configuration-transaction-generator).

#### Transaction execution steps
* Org1和Org2的admin分别登入客户端
* Org1admin发布一个API
* Org2admin申请获得调用该API的权限
* Org2admin请求改API
* Org1admin(DataOwner)验证权限返回数据
* Org1admin获得数据


## Running the sample program

There are two options available for running the Data-Trading-Platform sample

##### Terminal Window 1

```
cd fabric-samples/balance-transfer

./runApp.sh

```

* This lauches the required network on your local machine
* Installs the fabric-client and fabric-ca-client node modules
* And, starts the node app on PORT 4000

##### Terminal Window 2
* Start the simulation web service of data owner.

```
go run DataOwnerDataBase/go-server.go
```

##### Terminal Window 3


In order for the following shell script to properly parse the JSON, you must install ``jq``:

instructions [https://stedolan.github.io/jq/](https://stedolan.github.io/jq/)

With the application started in terminal 1, next, test the APIs by executing the script - **testAPIs.sh**:
```
cd fabric-samples/balance-transfer

./testAPIs.sh

```
note：别忘了把submitAPI里API的URL的ip地址部分改成本机IP，以便测试（因为DataOwnerDataBase是运行在本机上的）。



### Network configuration considerations

You have the ability to change configuration parameters by either directly editing the network-config.json file or provide an additional file for an alternative target network. The app uses an optional environment variable "TARGET_NETWORK" to control the configuration files to use. For example, if you deployed the target network on Amazon Web Services EC2, you can add a file "network-config-aws.json", and set the "TARGET_NETWORK" environment to 'aws'. The app will pick up the settings inside the "network-config-aws.json" file.

#### IP Address** and PORT information

If you choose to customize your docker-compose yaml file by hardcoding IP Addresses and PORT information for your peers and orderer, then you MUST also add the identical values into the network-config.json file. The paths shown below will need to be adjusted to match your docker-compose yaml file.

```
		"orderer": {
			"url": "grpcs://x.x.x.x:7050",
			"server-hostname": "orderer0",
			"tls_cacerts": "../artifacts/tls/orderer/ca-cert.pem"
		},
		"org1": {
			"ca": "http://x.x.x.x:7054",
			"peer1": {
				"requests": "grpcs://x.x.x.x:7051",
				"events": "grpcs://x.x.x.x:7053",
				...
			},
			"peer2": {
				"requests": "grpcs://x.x.x.x:7056",
				"events": "grpcs://x.x.x.x:7058",
				...
			}
		},
		"org2": {
			"ca": "http://x.x.x.x:8054",
			"peer1": {
				"requests": "grpcs://x.x.x.x:8051",
				"events": "grpcs://x.x.x.x:8053",
				...			},
			"peer2": {
				"requests": "grpcs://x.x.x.x:8056",
				"events": "grpcs://x.x.x.x:8058",
				...
			}
		}

```

#### Discover IP Address

To retrieve the IP Address for one of your network entities, issue the following command:

```
# this will return the IP Address for peer0
docker inspect peer0 | grep IPAddress
```

<a rel="license" href="http://creativecommons.org/licenses/by/4.0/"><img alt="Creative Commons License" style="border-width:0" src="https://i.creativecommons.org/l/by/4.0/88x31.png" /></a><br />This work is licensed under a <a rel="license" href="http://creativecommons.org/licenses/by/4.0/">Creative Commons Attribution 4.0 International License</a>.


