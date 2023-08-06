$(document).ready(function () {
    let userAgent;

    // Handle the form submission for the SIP configuration
    $("#sip-configuration").submit(function(event) {
        event.preventDefault();

        // Create a SIP User Agent with the provided parameters
        const server = $("#sip-server").val();
        const username = $("#sip-username").val();
        const password = $("#sip-password").val();

        const userAgent = new SIP.UA({
            uri: username + '@' + server,
            wsServers: ['wss://' + server],
            authorizationUser: username,
            password: password
        });

        // Register the user agent to the server
        userAgent.register();
    });

    // Handle the form submission for sending a SIP message
    $("#send-message").submit(function(event) {
        event.preventDefault();

        // Send a SIP message with the provided content
        const messageContent = $("#message").val();
        const session = userAgent.message('sip:receiver@server.com', messageContent);

        // Add the sent message to the log
        $("#message-log").append('<p>Sent: ' + messageContent + '</p>');
    });

    // Listen for incoming messages
    userAgent.on('message', function(message) {
        // Add the received message to the log
        $("#message-log").append('<p>Received: ' + message.body + '</p>');
    });

});