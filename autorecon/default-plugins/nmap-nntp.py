from autorecon.plugins import ServiceScan

class NmapNNTP(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "Nmap NNTP"
		self.tags = ['default', 'safe', 'nntp']

	def configure(self):
		self.match_service_name('^nntp')

	async def run(self, service):
		await service.execute('nmap {nmap_extra} -sV -p {port} --script="banner,nntp-ntlm-info" -oA "{scandir}/{protocol}_{port}_nntp_nmap" {address}')
