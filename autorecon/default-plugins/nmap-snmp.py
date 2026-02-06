from autorecon.plugins import ServiceScan

class NmapSNMP(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "Nmap SNMP"
		self.tags = ['default', 'safe', 'snmp']

	def configure(self):
		self.match_service_name('^snmp')

	async def run(self, service):
		await service.execute('nmap {nmap_extra} -sV -p {port} --script="banner,(snmp* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" -oA "{scandir}/{protocol}_{port}_snmp-nmap" {address}')
