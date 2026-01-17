from flask import Flask, request, jsonify, render_template
import mysql.connector
from lxml import etree

app = Flask(__name__)

# db = mysql.connector.connect(
#     host="localhost",
#     user="root",
#     password="root",
#     database="shop"
# )

# @app.route("/products", methods=["GET"])
# def get_products():
#     cursor = db.cursor(dictionary=True)
#     cursor.execute("SELECT * FROM products")
#     return jsonify(cursor.fetchall())

@app.route("/")
def home():
    return render_template("index.html")
@app.route("/labone")
def labone():
    return render_template("lab1.html")
@app.route("/labtwo")
def labtwo():
    return render_template("lab2.html")

@app.route("/xml", methods=["POST"])
def parse_xml():
    xml_data = request.data

    parser = etree.XMLParser(
        resolve_entities=True, #DTD allowed
        load_dtd=True, #Parameter entities allowed
        no_network=False #Outbound HTTP allowed
    )

    root = etree.fromstring(xml_data, parser)

    return jsonify({"result": root.text})

from lxml import etree
from flask import request, jsonify

class XXEResolver(etree.Resolver):
    def resolve(self, url, pubid, context):
        print("[XXE] Fetching:", url)
        return self.resolve_filename(url, context)

@app.route("/blind_xml", methods=["POST"])
def parse_blind_xml():
    xml_data = request.data

    parser = etree.XMLParser(
        load_dtd=True,
        resolve_entities=True
    )

    parser.resolvers.add(XXEResolver())

    root = etree.fromstring(xml_data, parser)

    product_id = root.findtext("productId")

    if not product_id or not product_id.isdigit():
        return jsonify({"error": "Invalid product ID"}), 400

    return jsonify({
        "message": "Product processed successfully",
        "productId": product_id
    })



if __name__ == "__main__":
    app.run(debug=True)
