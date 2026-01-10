import libxmljs from "libxmljs2";
export function getUserDetails(req, res) {
    const xml = req.body;
    console.log("Received XML:\n", xml);

    res.set("Content-Type", "application/xml");

    if (xml.includes("<userId>101</userId>")) {
        res.send(`
<?xml version="1.0"?>
<response>
    <status>success</status>
    <user>
        <id>101</id>
        <name>John Doe</name>
        <email>john@example.com</email>
    </user>
</response>
        `);
    } else {
        res.send(`
<?xml version="1.0"?>
<response>
    <status>error</status>
    <message>User not found</message>
</response>
        `);
    }
}

export function getDTDdetails(req, res) {
    const xml = req.body;
    console.log("Received XML:\n", xml);

    res.set("Content-Type", "application/xml");

    res.send(`
<?xml version="1.0"?>
<!DOCTYPE response [
    <!ELEMENT response (status, user)>
    <!ELEMENT status (#PCDATA)>
    <!ELEMENT user (id, name, email)>
    <!ELEMENT id (#PCDATA)>
    <!ELEMENT name (#PCDATA)>
    <!ELEMENT email (#PCDATA)>
]>
<response>
    <status>success</status>
    <user>
        <id>101</id>
        <name>John Doe</name>
        <email>john@example.com</email>
    </user>
</response>
    `);
}

export function getExternalDTDdetails(req, res) {
    res.send(`
<?xml version="1.0"?>
<!DOCTYPE request SYSTEM "http://localhost:3000/external.dtd">
<request>
    <action>fetchUser</action>
    <userId>101</userId>
</request>
`)
}

export function getExternalPublicDTDdetails(req, res) {
    res.set("Content-Type", "application/xml");
    res.send(`
<?xml version="1.0"?>
<!DOCTYPE request SYSTEM "https://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<request>
    <action>fetchUser</action>
    <userId>101</userId>
</request>
`);
}


const dataArray = [];

export function save_dtd_value(req, res) {
    try {
        const xmlString = req.body;

        const xmlDoc = libxmljs.parseXml(xmlString, {
            dtdload: true,
            noent: true
        });

        const value = xmlDoc.get("//value")?.text();

        if (!value) {
            return res.status(400).send(`
<response>
    <status>error</status>
    <message>Value missing</message>
</response>
            `);
        }

        // ✅ push every new value
        dataArray.push(value);

        let itemsXml = "";
        dataArray.forEach(item => {
            itemsXml += `<item>${item}</item>\n`;
        });

        res.set("Content-Type", "application/xml");
        res.send(`<?xml version="1.0"?>
<response>
    <status>success</status>
    <data>
        ${itemsXml}
    </data>
</response>`);
    } catch (err) {
        res.status(400).send(`
<response>
    <status>error</status>
    <message>${err.message}</message>
</response>
        `);
    }
}
                               