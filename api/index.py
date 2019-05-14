import json
from http.server import BaseHTTPRequestHandler
from pyhaproxy.parse import Parser


def parse_file(fileString):
    # Build the configuration instance
    cfg_parser = Parser(filestring=fileString)
    configuration = cfg_parser.build_configuration()

    # Get all the frontend sections
    frontend_sections = configuration.frontends

    def parse_frontend(frontend_name):
        data = {
            "name": frontend_name,
            "unused": [],
            "backends": {}
        }
        # Find the frontend by name
        the_fe_section = configuration.frontend(frontend_name)

        # Get all acls of the frontend
        acls = the_fe_section.acls()

        # Get all backends of the frontend
        backends = the_fe_section.usebackends()

        # Visisted list of ACLs
        visited_acls = list(
            map(lambda x: {"name": x.name, "used": False}, acls))

        allData = {}
        for b in backends:
            backendData = {
                "name": b.backend_name,
                "acls": []
            }

            # Get all acl data
            for a in b.backend_condition.split(" "):
                if a == '':
                    backendData['acls'].append({"name": '', "condition": ''})
                    continue

                corrected_a = a if a[0] is not "!" else a[1:]
                acl_data = the_fe_section.acl(corrected_a)

                for v in visited_acls:
                    if v["name"] == corrected_a:
                        v["used"] = True
                        break
                aclData = {
                    "name": a,
                    "condition":  acl_data.value if acl_data is not None else a
                }
                backendData['acls'].append(aclData)

            if b.backend_name in allData:
                allData[b.backend_name]['acls'].extend(backendData['acls'])
            else:
                allData[b.backend_name] = backendData

        data['backends'] = allData
        data['unused'] = list(
            map(
                lambda x: x['name'],
                list(
                    filter(lambda x: x['used'] is False, visited_acls)
                )
            )
        )

        return data

    all_frontend_data = list(
        map(lambda f: parse_frontend(f.name), frontend_sections)
    )

    return all_frontend_data


class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_len = int(self.headers.get('Content-Length'))
        post_body = self.rfile.read(content_len)

        # Get file content from POST
        config_data = json.loads(post_body.decode('utf-8'))

        # Run parser for that haproxy.cfg
        output = json.dumps({"data": parse_file(config_data['config'])})

        # Respond with the generated JSON
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()

        self.wfile.write(str(output).encode())

        return

    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(str('{"data":"Hello world!"}').encode())
        return
