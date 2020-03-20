import re
import datetime, pytz
import atexit
import hashlib
import uuid
import os

from flask import Flask, Response
from apscheduler.schedulers.background import BackgroundScheduler

from cabby import create_client
from stix.core import STIXPackage

from pymisp import MISPEvent, MISPAttribute, MISPOrganisation
from io import StringIO


from logging.config import dictConfig

"""
Variables
"""
LISTEN_ADDRESS = os.getenv("CS_MISP_FEED_LISTEN_ADDRESS", "0.0.0.0")
LISTEN_PORT = os.getenv("CS_MISP_FEED_LISTEN_PORT", 8080)
SCHEDULED_INTERVAL = int(os.getenv("CS_MISP_FEED_SCHEDULED_INTERVAL",
                                   str(60 * 30)))

CYBERSAIYAN_FEED_URL = \
    os.getenv("CS_TAXII_URL", "infosharing.cybersaiyan.it")
CYBERSAIYAN_COLLECTION_NAME = \
    os.getenv("CS_TAXII_COLLECTION_NAME",'CS-COMMUNITY-TAXII')
TAXII_USE_TLS = True
TAXII_DISCOVERY_PATH = \
    os.getenv("CS_TAXII_DISCOVERY_SERVICE", '/taxii-discovery-service')

utc = pytz.UTC

TLPS = ["white", "green", "amber", "red"]
TLP = {**dict(zip(TLPS,range(len(TLPS)))),**{i:TLPS[i]
                                             for i in range(len(TLPS))}}
fake_index_template = """<html>
<head>
<title>CyberSaiyan Info-Sharing - TAXII to MISP</title>
</head>
<body>
<h1>Cyber Saiyan Info-Sharing - TAXII to MISP</h1>
<hr>
<pre>
<a href="#">../</a>
{body}
</pre>
<hr>
</body>
</html>
""".strip()


"""
App declaration
"""

dictConfig({
    'version': 1,
    'formatters': {'default': {
        'format': '[%(asctime)s] %(levelname)s in %(module)s: %(message)s',
    }},
    'handlers': {'wsgi': {
        'class': 'logging.StreamHandler',
        'stream': 'ext://sys.stdout',
        'formatter': 'default'
    }},
    'root': {
        'level': 'INFO',
        'handlers': ['wsgi']
    }
})


app = Flask(__name__)
scheduler = BackgroundScheduler()


"""
Variables to fill for feed
"""

f_hashes, f_manifest, f_events = list(), dict(), dict()


"""
Application handlers
"""

@app.route('/')
def srv_get_event_list():
    links = []
    for event_uuid in f_manifest:
        links.append('<a href="{u}.json">{u}.json</a>\t01-Jan-1970 00:00\t-'
                     .format(u=event_uuid))
    links.append('<a href="{filename}">{filename}</a>\t01-Jan-1970 00:00\t-'
                 .format(filename="hashes.csv"))
    links.append('<a href="{filename}">{filename}</a>\t01-Jan-1970 00:00\t-'
                 .format(filename="manifest.json"))
    links = '\n'.join(links)

    return fake_index_template.format(body=links)

@app.route('/<path:path>')
def srv_get_event(path):
    path = path.lower()
    if path == "manifest.json":
        return f_manifest, 200
    elif path.lower() == "hashes.csv":
        return Response('\n'.join(['{},{}'.format(f_hash[0], f_hash[1])
                                   for f_hash in f_hashes]),
                        mimetype="text/csv")
    elif path == "events":
        return f_events
    else:
        path = re.sub(r'.(json|csv)$', "", path)
        if path in f_events:
            return {
                "Event": f_events[path]
            }
        else:
            return "<h1>404 Not found</h1>", 404

def poll_taxii():
    global f_hashes, f_manifest, f_events
    results_dict = {}
    client = create_client(
        CYBERSAIYAN_FEED_URL,
        use_https=TAXII_USE_TLS,
        discovery_path=TAXII_DISCOVERY_PATH
    )

    blocks = client.poll(collection_name=CYBERSAIYAN_COLLECTION_NAME)

    for block in blocks:
        content = block.content
        if content:
            if type(content) == str:
                continue
            elif type(content) == bytes:
                content = content.decode('utf-8')
        pkg = STIXPackage.from_xml(StringIO(content))

        title = pkg.stix_header.title
        information_source = pkg.stix_header.information_source.identity.name

        cs_event = (title, information_source)
        cs_event_hash = hash(cs_event)
        cs_event_md5 = hashlib.md5()
        cs_event_md5.update((title+information_source).encode('utf-8'))


        if cs_event_hash not in results_dict:
            results_dict[cs_event_hash] = MISPEvent()

        m_ev = results_dict[cs_event_hash]
        m_ev.info = str(pkg.stix_header.description)
        m_ev.analysis = 0
        m_ev.uuid = str(uuid.UUID(cs_event_md5.hexdigest()))

        #m_ev.org = "CyberSaiyan"

        csorg = MISPOrganisation()
        csorg.name = "CyberSaiyan"
        csorg.uuid = "8aaa81ed-72ef-4fb1-8e96-fa1bc200faeb"
        m_ev.orgc = csorg

        marking = pkg.stix_header.handling.marking
        tlp = 0
        found_tlp = False
        for m in marking:
            for struct in m.marking_structures:
                if struct._XSI_TYPE == "tlpMarking:TLPMarkingStructureType":
                    found_tlp = True
                    tlp = max(TLP[struct.color.lower()], tlp)
        if tlp == 0 and not found_tlp:
            tlp = TLP["amber"]
        m_ev.add_tag("tlp:"+TLP[tlp])
        m_ev.add_tag("CyberSaiyan")

        indicators = pkg.indicators
        last_ts = utc.localize(datetime.datetime(1970,1,1))
        for indicator in indicators:
            cur_ts = indicator.timestamp
            if cur_ts > last_ts:
                last_ts = cur_ts
            obj = indicator.observable.object_
            obj_d = obj.properties.to_dict()

            attr_type = obj_d["xsi:type"]
            if attr_type == "AddressObjectType":

                attr = MISPAttribute()
                attr.category = "Network activity"
                attr.type = "ip-dst"
                attr.value = obj_d["address_value"]
                attr.disable_correlation = False
                attr.to_ids = True

            elif attr_type == "DomainNameObjectType":

                attr = MISPAttribute()
                attr.category = "Network activity"
                attr.type = "domain"
                attr.value = obj_d["value"]
                attr.disable_correlation = False
                attr.to_ids = True

            elif attr_type == "URIObjectType":

                attr = MISPAttribute()
                attr.category = "Network activity"
                attr.type = "url"
                attr.value = obj_d["value"]
                attr.disable_correlation = False
                attr.to_ids = True


            elif attr_type == "FileObjectType":
                hash_type = obj_d["hashes"][0]["type"]["value"].lower()
                hash_value = obj_d["hashes"][0]["simple_hash_value"]

                attr = MISPAttribute()
                attr.category = "Payload delivery"
                assert hash_type in ('md5', "sha1", "sha224",
                                     "sha256", "sha384", "sha512", "ssdeep")
                attr.type = hash_type
                attr.value = hash_value
                attr.disable_correlation = False
                attr.to_ids = True

            m_ev.date = last_ts
            m_ev.attributes.append(attr)

    c_hashes, c_manifest, c_events = list(), dict(), dict()

    for event in results_dict.values():
        e_feed = event.to_feed(with_meta=True).get("Event")
        c_hashes += [[h, event.uuid] for h in e_feed.pop("_hashes")]
        c_manifest.update(e_feed.pop('_manifest'))
        c_events[event.uuid] = e_feed

    f_hashes, f_manifest, f_events = c_hashes, c_manifest, c_events


def task_poll_taxii():
    try:
        poll_taxii()
    except Exception as e:
        app.logger.exception("Error during poll")

if __name__ == "__main__":
    app.logger.info("Importing events for the first time")
    task_poll_taxii()
    app.logger.info("Done")
    scheduler.add_job(func=task_poll_taxii,
                      trigger="interval",
                      seconds=SCHEDULED_INTERVAL)
    scheduler.start()
    atexit.register(lambda: scheduler.shutdown())

    app.run(host=LISTEN_ADDRESS, port=LISTEN_PORT)
