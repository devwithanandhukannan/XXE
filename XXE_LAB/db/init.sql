USE shop;

CREATE TABLE products (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100),
    price DECIMAL(10,2),
    quantity INT
);

INSERT INTO products (name, price, quantity) VALUES
('Laptop', 999.99, 10),
('Phone', 499.99, 25),
('Keyboard', 49.99, 50),
('Mouse', 29.99, 80);
