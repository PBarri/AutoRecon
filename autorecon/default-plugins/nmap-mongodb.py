from autorecon.plugins import ServiceScan

class NmapMongoDB(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "Nmap MongoDB"
		self.tags = ['default', 'safe', 'databases']

	def configure(self):
		self.match_service_name('^mongod')

	async def run(self, service):
		await service.execute('nmap {nmap_extra} -sV -p {port} --script="banner,(mongodb* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" -oA "{scandir}/{protocol}_{port}_mongodb_nmap" {address}')
