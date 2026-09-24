import io
import unittest

from rich.console import Console

from core.scanner import NmapScanner


SAMPLE_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up" />
    <address addr="192.0.2.10" addrtype="ipv4" />
    <hostnames><hostname name="web.lab" type="PTR" /></hostnames>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open" />
        <service name="https" product="Apache httpd" version="2.4.49">
          <cpe>cpe:/a:apache:http_server:2.4.49</cpe>
        </service>
        <script id="http-title" output="Lab landing page" />
      </port>
      <port protocol="tcp" portid="80">
        <state state="closed" />
        <service name="http" />
      </port>
    </ports>
  </host>
</nmaprun>"""


class NmapParserTests(unittest.TestCase):
    def test_extracts_host_open_port_service_cpe_and_scripts(self):
        scanner = NmapScanner(console=Console(file=io.StringIO()))

        hosts = scanner._parse_xml(SAMPLE_XML)

        self.assertEqual(len(hosts), 1)
        self.assertEqual(hosts[0].ip, "192.0.2.10")
        self.assertEqual(hosts[0].hostname, "web.lab")
        self.assertEqual(len(hosts[0].ports), 1)
        self.assertEqual(hosts[0].ports[0].port, 443)
        self.assertEqual(hosts[0].ports[0].version, "2.4.49")
        self.assertEqual(hosts[0].ports[0].cpes, ["cpe:/a:apache:http_server:2.4.49"])
        self.assertEqual(hosts[0].ports[0].scripts["http-title"], "Lab landing page")

    def test_malformed_xml_returns_no_hosts(self):
        scanner = NmapScanner(console=Console(file=io.StringIO()))

        self.assertEqual(scanner._parse_xml("<nmaprun><host>"), [])


if __name__ == "__main__":
    unittest.main()
