from autorecon.plugins import ServiceScan

class NmapRPC(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "Nmap MSRPC"
		self.tags = ['default', 'rpc']

	def configure(self):
		self.match_service_name(['^msrpc', '^rpcbind', '^erpc'])

	async def run(self, service):
		await service.execute('nmap {nmap_extra} -sV -p {port} --script="banner,msrpc-enum,rpc-grind,rpcinfo" -oA "{scandir}/{protocol}_{port}_rpc_nmap" {address}')
