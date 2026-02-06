from autorecon.plugins import ServiceScan

class NmapOracle(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "Nmap Oracle"
		self.tags = ['default', 'safe', 'databases']

	def configure(self):
		self.match_service_name('^oracle')

	def manual(self, service, plugin_was_run):
		service.add_manual_command('Brute-force SIDs using Nmap:', 'nmap {nmap_extra} -sV -p {port} --script="banner,oracle-sid-brute" -oA "{scandir}/{protocol}_{port}_oracle_sid-brute_nmap" {address}')

	async def run(self, service):
		await service.execute('nmap {nmap_extra} -sV -p {port} --script="banner,(oracle* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" -oA "{scandir}/{protocol}_{port}_oracle_nmap" {address}')
