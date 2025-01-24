import tkinter as tk
from tkinter import messagebox
import socket
import json
import threading
import sys

class MessengerClient:
    def __init__(self):
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_address = (sys.argv[1], int(sys.argv[2]))
        self.username = None
        self.friends = []
        self.friend_requests = []
        self.chat_windows = {}
        self.group_names=[]

        self.root = tk.Tk()
        self.root.title("Messenger Client")
        self.root.geometry("500x400")
        self.root.protocol("WM_DELETE_WINDOW", lambda: self.logout())

        self.connect_to_server()

        self.running = True
        self.receive_thread = threading.Thread(target=self.receive_messages)
        self.receive_thread.start()

        self.login_screen()

    def connect_to_server(self):
        try:
            self.client_socket.connect(self.server_address)
            self.client_socket.setblocking(False)
        except socket.error as e:
            messagebox.showerror("Error", f"Could not connect to server: {e}")
            self.root.quit()

    def send_request(self, request):
        try:
            self.client_socket.send(json.dumps(request).encode() + b'\n')
        except socket.error as e:
            messagebox.showerror("Error", f"Failed to send request: {e}")

    def receive_messages(self):
        buffer = ""
        while self.running:
            try:
                data = self.client_socket.recv(1024).decode()
                if not data:
                    break

                buffer += data
                while '\n' in buffer:
                    message, buffer = buffer.split('\n', 1)
                    response = json.loads(message)
                    self.handle_response(response)
            except socket.error:
                continue


    def handle_login_success(self, response):
        self.username = response.get("username")
        self.friends = response.get("friends", [])
        self.friend_requests = response.get("friend_requests", [])
        self.group_names = response.get("groups", [])
        self.main_screen()

    def handle_accept_friend_request_success(self, response):
        sender = response.get("sender")
        self.friend_requests.remove(sender)
        self.friends.append(sender)
        self.main_screen()

    def handle_friend_request_accepted_success(self, response):
        accepter = response.get("accepter")
        self.friends.append(accepter)
        self.main_screen()

    def handle_receive_message(self, response):
        id = response.get("id")
        sender = response.get("sender")
        text = response.get("content")
        if id in self.chat_windows:
            chat_window = self.chat_windows[id]
            chat_text = chat_window.children.get('!text')
            
            if chat_text:
                self.root.after(0, self.display_message, sender, text, chat_text)

    def handle_create_group(self, response):
        group_name = response.get("name")
        self.group_names.append(group_name)
        self.update_groups_list()


    def frined_popup(self, sender):
        request_window = tk.Toplevel(self.root)
        request_window.title("Friend Request")
        request_window.geometry("300x150")

        tk.Label(request_window, text=f"New friend request from {sender}").pack(pady=10)

        def accept_request():
            self.accept_friend_request(sender)
            print("Request accepted")
            request_window.destroy()

        def ignore_request():
            messagebox.showinfo("Ignored", f"You ignored the friend request from {sender}.")
            self.friend_requests.remove(sender)
            request_window.destroy()

        tk.Button(request_window, text="Accept", command=accept_request).pack(side=tk.LEFT, padx=20, pady=20)
        tk.Button(request_window, text="Ignore", command=ignore_request).pack(side=tk.RIGHT, padx=20, pady=20)

    def handle_incoming_friend_request(self, response):
        sender = response.get("sender")

        self.friend_requests.append(sender)
        self.frined_popup(sender)
       

    def login_screen(self):
        for widget in self.root.winfo_children():
            widget.destroy()

        tk.Label(self.root, text="Username").pack()
        self.username_entry = tk.Entry(self.root)
        self.username_entry.pack()

        tk.Label(self.root, text="Password").pack()
        self.password_entry = tk.Entry(self.root, show="*")
        self.password_entry.pack()

        tk.Button(self.root, text="Login", command=self.login).pack()
        tk.Button(self.root, text="Register", command=self.register).pack()


    def main_screen(self):
        for widget in self.root.winfo_children():
            widget.destroy()

        tk.Label(self.root, text=f"Logged in as {self.username}").pack()

        main_frame = tk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True)

        friends_frame = tk.Frame(main_frame)
        friends_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        tk.Label(friends_frame, text="Friends:").pack()
        self.friends_listbox = tk.Listbox(friends_frame)
        self.friends_listbox.pack(fill=tk.BOTH, expand=True)
        
        if self.friend_requests:
            for request in self.friend_requests:
                self.frined_popup(request)

        self.update_friends_list()

        def friend_callback(event):
            if self.friends_listbox.curselection():
                index = self.friends_listbox.curselection()[0]
                rec = self.friends[index]
                self.incomming_chat(rec)

        self.friends_listbox.bind("<<ListboxSelect>>", friend_callback)

        groups_frame = tk.Frame(main_frame)
        groups_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        tk.Label(groups_frame, text="Groups:").pack()
        self.groups_listbox = tk.Listbox(groups_frame)
        self.groups_listbox.pack(fill=tk.BOTH, expand=True)
        self.update_groups_list()

        def group_callback(event):
            if self.groups_listbox.curselection():
                index = self.groups_listbox.curselection()[0]
                group = self.group_names[index]
                self.join_group(group)

        self.groups_listbox.bind("<<ListboxSelect>>", group_callback)


        tk.Button(self.root, text="Add Friend", command=self.add_friend_screen).pack()
        tk.Button(self.root, text="Add Group", command=self.create_group_screen).pack()
        tk.Button(self.root, text="Delete Group", command=self.delete_group_screen).pack()
        tk.Button(self.root, text="Active", command=self.get_active_users).pack()
        tk.Button(self.root, text="Log out", command=self.logout).pack()


    def update_groups_list(self):
        self.groups_listbox.delete(0, tk.END)
        for group in self.group_names:
            self.groups_listbox.insert(tk.END, group)

    def update_friends_list(self):
        self.friends_listbox.delete(0, tk.END)
        for friend in self.friends:
            self.friends_listbox.insert(tk.END, friend)

    def get_active_users(self):
        self.send_request({"action": "get_active_users", "username": self.username})
    
    def message_screen(self, recipient):
        if recipient in self.chat_windows:
            chat_window = self.chat_windows[recipient]
            chat_window.lift()
            return
        
        chat_window = tk.Toplevel(self.root)
        chat_window.title(f"Chat with {recipient}")
        chat_window.protocol("WM_DELETE_WINDOW", lambda: self.close_chat_window(recipient))

        chat_text = tk.Text(chat_window, state="disabled", height=20, width=50)
        chat_text.pack()
        self.chat_windows[recipient] = chat_window

        message_entry = tk.Entry(chat_window)
        message_entry.pack()

        def send_current_message():
            content = message_entry.get()
            if content.strip():
                self.send_message(recipient, content)
                self.display_message(self.username, content, chat_text)
                message_entry.delete(0, tk.END)

        tk.Button(chat_window, text="Send", command=send_current_message).pack()
        self.send_request({"action": "send_message","sender": self.username,"recipient": recipient,"content": " joined the conversation"})


    def group_chat_screen(self, group_name):
        if group_name in self.chat_windows:
            chat_window = self.chat_windows[group_name]
            chat_window.lift()
            return

        chat_window = tk.Toplevel(self.root)
        chat_window.title(f"Group: {group_name}")
        chat_window.protocol("WM_DELETE_WINDOW", lambda: self.close_groupchat_window(group_name))

        chat_text = tk.Text(chat_window, state="disabled", height=20, width=50)
        chat_text.pack()
        self.chat_windows[group_name] = chat_window

        message_entry = tk.Entry(chat_window)
        message_entry.pack()

        def send_current_message():
            content = message_entry.get()
            if content:
                self.send_group_message(group_name, content)
                self.display_message(self.username, content, chat_text)
                message_entry.delete(0, tk.END)

        tk.Button(chat_window, text="Send", command=send_current_message).pack()

    def join_group(self,group_name):
        self.send_request({"action":"join_group","group":group_name,"user":self.username})
    
    def send_group_message(self, name, content):
        self.send_request({"action": "group_message","sender": self.username,"group": name,"content": content})
     

    def display_message(self, sender, content, chat_text=None):
        if chat_text:
            chat_text.config(state="normal")
            chat_text.insert(tk.END, f"{sender}: {content}\n")
            chat_text.config(state="disabled")

    def send_message(self, recipient, content):
        self.send_request({"action": "send_message","sender": self.username,"recipient": recipient,"content": content})

    def incomming_chat(self,recipient):
        self.send_request({"action": "create_chat","sender": self.username,"recipient": recipient})
        
    def close_chat_window(self, user):
        chat_window = self.chat_windows.pop(user, None)
        if chat_window:
            self.send_request({"action": "disconnected","sender": self.username,"recipient":user})
            chat_window.destroy()

    def close_groupchat_window(self, group):
        chat_window = self.chat_windows.pop(group, None)
        if chat_window:
            self.send_request({"action": "disconnected_group","sender": self.username,"group":group})
            chat_window.destroy()

    def create_group_screen(self):
        group_window = tk.Toplevel(self.root)
        group_window.title("Create Group")

        tk.Label(group_window, text="Group Name:").pack()
        group_name_entry = tk.Entry(group_window)
        group_name_entry.pack()

        def create_group():
            group_name = group_name_entry.get()
            if not group_name:
                messagebox.showerror("Error", "Group name cannot be empty.")
                return
            self.send_request({"action": "create_group", "group_name": group_name})
            group_window.destroy()

        tk.Button(group_window, text="Create", command=create_group).pack()

    def delete_group_screen(self):
        group_window = tk.Toplevel(self.root)
        group_window.title("Delete Group")

        tk.Label(group_window, text="Group Name:").pack()
        group_name_entry = tk.Entry(group_window)
        group_name_entry.pack()

        def delete_group():
            group_name = group_name_entry.get()
            if not group_name:
                messagebox.showerror("Error", "Group name cannot be empty.")
                return
            self.send_request({"action": "delete", "group": group_name})
            group_window.destroy()

        tk.Button(group_window, text="Delete", command=delete_group).pack()


    def send_group_message(self, group_name, content):
        self.send_request({"action": "send_group_message", "group_name": group_name, "sender": self.username, "content": content})


    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        if not username or not password:
            messagebox.showerror("Error", "Username and password cannot be empty.")
            return

        self.send_request({"action": "login", "username": username, "password": password})

    def register(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        if not username or not password:
            messagebox.showerror("Error", "Username and password cannot be empty.")
            return

        self.send_request({"action": "register", "username": username, "password": password})

    def add_friend_screen(self):
        self.friend_entry = tk.Toplevel(self.root)
        self.friend_entry.title("Add Friend")

        tk.Label(self.friend_entry, text="Enter friend's username:").pack()
        self.friend_username_entry = tk.Entry(self.friend_entry)
        self.friend_username_entry.pack()
        tk.Button(self.friend_entry, text="Send Request", command=self.send_friend_request).pack()

    def send_friend_request(self):
        recipient = self.friend_username_entry.get()
        if not recipient:
            messagebox.showerror("Error", "Friend's username cannot be empty.")
            return

        self.send_request({"action": "send_friend_request", "sender": self.username, "recipient": recipient})
        self.friend_entry.destroy()

    def accept_friend_request(self, sender):
        self.send_request({"action": "accept_friend_request", "accepter": self.username, "sender": sender})

    def logout(self):
        print(self.friends)
        print(self.friend_requests)
        self.send_request({"action": "logout", "username": self.username})
        self.running = False
        self.client_socket.close()
        self.root.quit()

    def handle_response(self, response):
        action = response.get("action")
        if response.get("status") == "success":
            if action == "login":
                self.handle_login_success(response)
            elif action == "accept_friend_request":
                self.handle_accept_friend_request_success(response)
            elif action == "friend_request_accepted":
                self.handle_friend_request_accepted_success(response)
            elif action == "incoming_friend_request":
                self.handle_incoming_friend_request(response)
            elif action == "receive_message":
                self.handle_receive_message(response)
            elif action == "new_chat":
                self.message_screen(response.get("sender"))
            elif action == "user_disconnected":
                self.handle_receive_message(response)
            elif action == "group_created":
                self.handle_create_group(response)
            elif action == "join":
                self.group_chat_screen(response.get("name"))
            elif action == "group_disconnected":
                self.handle_receive_message(response)
            elif action == "group_deleted":
                self.group_names.remove(response.get("id"))
                self.update_groups_list()

            else:
                messagebox.showinfo("Success", response.get("message", response["message"]))
        else:
            messagebox.showerror("Error", response.get("message", response["message"]))

    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    client = MessengerClient()
    client.run()
