import sys
import networkx as nx
import matplotlib.pyplot as plt
import bcrypt
from PyQt5.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QLineEdit, QGridLayout, QMessageBox
from PyQt5.QtGui import QPixmap, QPalette, QBrush

app = QApplication(sys.argv)

# Create a QMainWindow
window = QMainWindow()
window.setWindowTitle('Network Traffic Analyzer')
window.setGeometry(100, 100, 800, 600)

# Set a background image
palette = QPalette()
bg_image = QPixmap(r"D:\DMA PBL\pblimage.jpg")  # background image
palette.setBrush(QPalette.Background, QBrush(bg_image))
window.setPalette(palette)

central_widget = QWidget(window)
window.setCentralWidget(central_widget)

layout = QVBoxLayout()

form_layout = QGridLayout()

source_label = QLabel('Source IP:')
source_input = QLineEdit()
form_layout.addWidget(source_label, 0, 0)
form_layout.addWidget(source_input, 0, 1)

dest_label = QLabel('Destination IP:')
dest_input = QLineEdit()
form_layout.addWidget(dest_label, 1, 0)
form_layout.addWidget(dest_input, 1, 1)

password_label = QLabel('Password:')
password_input = QLineEdit()
password_input.setEchoMode(QLineEdit.Password)
form_layout.addWidget(password_label, 2, 0)
form_layout.addWidget(password_input, 2, 1)

layout.addLayout(form_layout)

button_layout = QHBoxLayout()

add_button = QPushButton('Add Traffic Data')
button_layout.addWidget(add_button)

graph_button = QPushButton('Display Traffic Graph')
button_layout.addWidget(graph_button)

# Add a button for displaying distances
distance_button = QPushButton('Display Distances')
button_layout.addWidget(distance_button)

# Add a button and input field for removing IP address
remove_ip_label = QLabel('Remove IP Address:')
remove_ip_input = QLineEdit()
remove_button = QPushButton('Remove IP')
button_layout.addWidget(remove_ip_label)
button_layout.addWidget(remove_ip_input)
button_layout.addWidget(remove_button)

layout.addLayout(button_layout)

central_widget.setLayout(layout)

G = nx.DiGraph()

def add_traffic():
    source_ip = source_input.text()
    dest_ip = dest_input.text()
    password = password_input.text()

    if source_ip and dest_ip and password:
        # Encrypt the password using bcrypt
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        G.add_edge(source_ip, dest_ip)

        # Store traffic data in a text file
        with open('traffic_data.txt', 'a') as file:
            file.write(f'Source IP: {source_ip}, Destination IP: {dest_ip}, Password Hash: {password_hash.decode("utf-8")}\n')

        source_input.clear()
        dest_input.clear()
        password_input.clear()

add_button.clicked.connect(add_traffic)

def display_traffic_graph():
    if len(G) > 0:
        pos = nx.spring_layout(G)
        nx.draw(G, pos, with_labels=True, node_size=500, node_color='lightblue')
        plt.title("Network Traffic Analysis")
        plt.show()
    else:
        print("No traffic data to display.")

graph_button.clicked.connect(display_traffic_graph)

# Function to display distances of each IP address
def display_distances():
    distances = {}
    for node in G.nodes:
        distances[node] = nx.shortest_path_length(G, source=node)

    distance_message = "Distances of IP addresses:\n"
    for node, distance in distances.items():
        distance_message += f"{node}: {distance}\n"

    msg_box = QMessageBox()
    msg_box.setWindowTitle('Node Distances')
    msg_box.setText(distance_message)
    msg_box.exec_()

distance_button.clicked.connect(display_distances)

# Function to remove an IP address from the graph
def remove_ip():
    ip_to_remove = remove_ip_input.text()
    if ip_to_remove:
        try:
            G.remove_node(ip_to_remove)
            remove_ip_input.clear()
        except nx.NetworkXError:
            print(f"IP address {ip_to_remove} not found in the graph.")

remove_button.clicked.connect(remove_ip)

window.show()
sys.exit(app.exec_())