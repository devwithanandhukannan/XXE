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

if __name__ == "__main__":
    app.run(debug=True)
