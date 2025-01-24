#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <iostream>
#include <unordered_map>
#include <vector>
#include <fstream>
#include <mutex>
#include "json.hpp"

using json = nlohmann::json;

#define BUFFER_SIZE 1024

std::unordered_map<std::string, int> clients;
std::unordered_map<std::string, std::vector<std::string>> groups;
std::vector<std::string> group_names; 
json users;
std::mutex mutex;

void load_users(std::string file_name,json& obj) {
    std::ifstream file(file_name);
    if (file.is_open()) {
        file >> obj;
        file.close();
    } else {
        obj = json::object();
    }
}

void save_users(std::string file_name,json& obj) {
    std::ofstream file(file_name);
    if (file.is_open()) {
        file << obj.dump(4);
        file.close();
    }
}

void send_response(int client_socket, const std::string &action, const json &response) {
    json full_response = response;
    full_response["action"] = action;
    std::string response_str = full_response.dump() + "\n";
    std::cout<<"SERVER SEND: "<<response_str<<" to "<< client_socket<<std::endl;
    send(client_socket, response_str.c_str(), response_str.size(), 0);
}

void handle_register(const json &message, int client_socket) {
    std::lock_guard<std::mutex> lock(mutex);
    std::string username = message["username"];
    std::string password = message["password"];

    if (users.contains(username)) {
        send_response(client_socket, "register", { {"status", "error"}, {"message", "User already exists"} });
    } else {
        users[username] = { {"friend_requests", json::array()}, {"friends", json::array()}, {"password", password} };
        save_users("users.json",users);
        send_response(client_socket, "success", { {"status", "success"},{"message","Registration successful"} });
    }
}

void handle_login(const json &message, int client_socket) {
    std::lock_guard<std::mutex> lock(mutex);
    std::string username = message["username"];
    std::string password = message["password"];

    if(clients.find(username) != clients.end()){
        send_response(client_socket, "login", { {"status", "error"}, {"message", "User already logged in"} });
    }
    else if(users.contains(username) && users[username]["password"] == password) {
        clients[username] = client_socket;

        json pending_requests = users[username]["friend_requests"];

        send_response(client_socket, "login", { 
            {"status", "success"},
            {"username", username},
            {"friends", users[username]["friends"]}, 
            {"friend_requests", pending_requests} ,
            {"groups", group_names}
        });

        users[username]["friend_requests"] = json::array();
        save_users("users.json",users);
    } else {
        send_response(client_socket, "login", { {"status", "error"}, {"message", "Invalid login data"} });
    }
}

void handle_logout(const json &message, int client_socket) {
    std::lock_guard<std::mutex> lock(mutex);
    std::string username = message["username"];

    if (clients.find(username) != clients.end()) {
        clients.erase(username);
        for(auto x : clients) std::cout<<x.first<<std::endl;
        send_response(client_socket, "logout", { {"status", "success"}, {"message", "Logged out successfully"} });
        close(client_socket);
    } else {
        send_response(client_socket, "logout", { {"status", "error"}, {"message", "User not logged in"} });
    }
}

void handle_friend_request(const json &message, int client_socket) {
    std::lock_guard<std::mutex> lock(mutex);
    std::string sender = message["sender"];
    std::string recipient = message["recipient"];

    if (!users.contains(recipient)) {
        send_response(client_socket, "send_friend_request", { {"status", "error"}, {"message", "User does not exist"} });
        return;
    }

    if(sender==recipient){
        send_response(client_socket, "send_friend_request", { {"status", "error"}, {"message", "Are you that lonely"} });
        return;
    }

    auto &sender_friends = users[sender]["friends"];
    auto &sender_list = users[recipient]["friend_requests"];
    if (std::find(sender_friends.begin(), sender_friends.end(), recipient) != sender_friends.end()) {
        send_response(client_socket, "send_friend_request", { {"status", "error"}, {"message", "You are already friends"} });
        return;
    }else if(std::find(sender_list.begin(), sender_list.end(), recipient) != sender_list.end()){
        send_response(client_socket, "send_friend_request", { {"status", "error"}, {"message", "You've send friend request already"} });
        return;
    }

    if (clients.find(recipient) != clients.end()) {
        int recipient_socket = clients[recipient];
        send_response(recipient_socket, "incoming_friend_request", { {"sender", sender},{"status","success"}});
    }else{
        users[recipient]["friend_requests"].push_back(sender);
        save_users("users.json",users);
    }


    send_response(client_socket, "success", { {"status", "success"}, {"message", "Friend request sent"} });
}


void handle_accept_friend(const json &message, int client_socket) {
    std::lock_guard<std::mutex> lock(mutex);
    std::string accepter = message["accepter"];
    std::string sender = message["sender"];

    if (!users.contains(sender)) {
        send_response(client_socket, "accept_friend_request", { {"status", "error"}, {"message", "Sender does not exist"} });
        return;
    }

    users[accepter]["friends"].push_back(sender);
    users[sender]["friends"].push_back(accepter);
    users[accepter]["friend_requests"] = json::array();
    save_users("users.json",users);

    if (clients.find(sender) != clients.end()) {
        int sender_socket = clients[sender];
        send_response(sender_socket, "friend_request_accepted", {{"accepter", accepter}, {"status", "success"}});
    }

    send_response(client_socket, "accept_friend_request", {{"sender",sender}, {"status", "success"}, {"message", "Friend request accepted"} });
}

void handle_send_message(const json &message, int client_socket) {
    std::string sender = message["sender"];
    std::string recipient = message["recipient"];
    std::string text = message["content"];

    std::cout<<"Message FROM: "<<sender<<" TO "<<recipient<<": "<<message<<std::endl;

    std::lock_guard<std::mutex> lock(mutex);
    if (clients.find(recipient) != clients.end()) {
        int recipient_socket = clients[recipient];
        send_response(recipient_socket, "receive_message", { {"id", sender},{"sender", sender}, {"content", text}, {"status", "success"} });
    } else {
        send_response(client_socket, "send_message", { {"status", "error"}, {"message", "Recipient is not online"} });
    }
}

void handle_get_active_users(int client_socket) {
    std::string active = "Active users:\n";
    std::lock_guard<std::mutex> lock(mutex);
    for (auto x : clients) active += x.first + "\n";
    send_response(client_socket, "send_message", { {"status", "success"}, {"message", active} });
}

void handle_new_chat(const json &message, int client_socket){
    std::string sender = message["sender"];
    std::string recipient = message["recipient"];
    
    std::lock_guard<std::mutex> lock(mutex);
    if (clients.find(recipient) != clients.end()) {
        int recipient_socket = clients[recipient];

        send_response(recipient_socket, "new_chat", { {"sender", sender}, {"status", "success"}});
        send_response(client_socket, "new_chat", { {"sender", recipient}, {"status", "success"}});
    } else {
        send_response(client_socket, "send_message", { {"status", "error"}, {"message", "Recipient is not online"} });
    }
}

void handle_disconnect_mess(const json &message, int client_socket){
    std::string sender = message["sender"];
    std::string recipient = message["recipient"];
    std::lock_guard<std::mutex> lock(mutex);
    if (clients.find(recipient) != clients.end()){
        int recipient_socket = clients[recipient];
        std::string text = "User disconnected";
    
        send_response(recipient_socket, "user_disconnected", {{"id",sender},{"sender", sender}, {"status", "success"},{"content",text}});
    }
}

void handle_disconnect_group(const json &message, int client_socket){
    std::string sender = message["sender"];
    std::string name = message["group"];
    std::string text = "User disconnected";
    std::lock_guard<std::mutex> lock(mutex);
    
    groups[name].erase(std::find(groups[name].begin(), groups[name].end(), sender));

    for (const auto &member : groups[name]) {
            if (clients.find(member) != clients.end()) {
                send_response(clients[member], "group_disconnected", {{"id",name},{"sender", sender}, {"status", "success"},{"content",text}});
        }
    
    }
}

void handle_delete_group(const json &message, int client_socket){
    std::string name = message["group"];
    std::lock_guard<std::mutex> lock(mutex);
    
    if(std::find(group_names.begin(), group_names.end(), name) == group_names.end()){
        send_response(client_socket, "send_message", {{"status", "error"},{"message","Chat doesn't exist"}});
        return;
    }

    if(!groups[name].empty()){
        send_response(client_socket, "send_message", {{"status", "error"},{"message","Someone use this chat"}});
        return;
    }
    
    groups.erase(name);
    group_names.erase(find(group_names.begin(), group_names.end(), name));

    for (auto x : clients) send_response(x.second, "group_deleted", {{"id",name}, {"status", "success"}});
}

void handle_create_group(const json &message, int client_socket) {
    std::string group_name = message["group_name"];

    std::lock_guard<std::mutex> lock(mutex);
    if(std::find(group_names.begin(), group_names.end(), group_name) != group_names.end() ) {
        send_response(client_socket, "create_group", { {"status", "error"}, {"message", "Group already exists"} });
    } else {
        std::cout<<group_name<<" CREATED"<<std::endl;
        group_names.push_back(group_name);
        groups[group_name] = std::vector<std::string>();
        for (auto x : clients) send_response(x.second, "group_created",{{"status","success"},{"name",group_name}});
    }
}

void handle_join_group(const json &message, int client_socket) {
    std::string group_name = message["group"];
    std::string username = message["user"];
    std::lock_guard<std::mutex> lock(mutex);
    auto &members = groups[group_name];
    if (std::find(members.begin(), members.end(), username) == members.end()) {
        members.push_back(username);
        send_response(client_socket, "join", { {"status", "success"}, {"name",group_name}});
        for (const auto &member : groups[group_name]) {
            if ((clients.find(member) != clients.end()) && member!=username) {
                send_response(clients[member], "receive_message", { {"id", group_name}, {"sender", username}, {"content", " joined chat"} ,{"status","success"}});
        }
    }
    }else{
        send_response(client_socket, "error", { {"status", "error"},{"message", "Fail to join the group"} });
    }
}

void handle_group_message(const json &message, int client_socket) {
    std::string name = message["group_name"];
    std::string sender = message["sender"];
    std::string content = message["content"];

    std::lock_guard<std::mutex> lock(mutex);
    
    for (const auto &member : groups[name]) {
        if ((clients.find(member) != clients.end()) && member!=sender) {
            send_response(clients[member], "receive_message", { {"id", name}, {"sender", sender}, {"content", content} ,{"status","success"}});
        }
    }
}


void *client_handler(void *socket_desc) {
    int client_socket = *(int *)socket_desc;
    char buffer[BUFFER_SIZE];

    while (true) {
        memset(buffer, 0, BUFFER_SIZE);
        int read_size = recv(client_socket, buffer, BUFFER_SIZE, 0);

        if (read_size <= 0) {
            close(client_socket);
            pthread_exit(NULL);
        }

        json message = json::parse(buffer);
        std::string action = message["action"];

        std::cout<<"SERVER RECEIVED: "<<message<<" "<<action<<std::endl;

        if (action == "register") {
            handle_register(message, client_socket);
        } else if (action == "login") {
            handle_login(message, client_socket);
        } else if (action == "logout") {
            handle_logout(message, client_socket);
        } else if (action == "get_active_users") {
            handle_get_active_users(client_socket);
        } else if (action == "send_friend_request") {
            handle_friend_request(message, client_socket);
        } else if (action == "accept_friend_request") {
            handle_accept_friend(message, client_socket);
        } else if (action == "send_message") {
            handle_send_message(message, client_socket);
        } else if (action == "create_chat") {
            handle_new_chat(message, client_socket);
        } else if (action == "disconnected"){
            handle_disconnect_mess(message,client_socket);
        } else if (action == "create_group") {
            handle_create_group(message, client_socket);
        } else if (action == "join_group"){
            handle_join_group(message,client_socket);
        } else if (action == "send_group_message") {
            handle_group_message(message, client_socket);
        } else if (action == "disconnected_group") {
            handle_disconnect_group(message, client_socket);
        } else if (action == "delete") {
            handle_delete_group(message, client_socket);
        }
    }
}

int main(int argc, char *argv[]) {
    load_users("users.json",users);
    int server_socket, client_socket;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_addr_size = sizeof(client_addr);

    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == -1) {
        perror("Could not create socket");
        exit(EXIT_FAILURE);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(atoi(argv[1]));

    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    listen(server_socket, 5);
    std::cout << "Server running on port " << argv[1] << std::endl;

    while (true) {
        client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_addr_size);
        if (client_socket < 0) {
            perror("Accept failed");
            continue;
        }
        std::cout << "Connected client IP: " << inet_ntoa(client_addr.sin_addr) << " "<<client_socket<<std::endl;

        pthread_t client_thread;
        pthread_create(&client_thread, NULL, client_handler, (void *)&client_socket);
        pthread_detach(client_thread);
    }

    close(server_socket);
    return 0;
}