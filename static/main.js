

$(document).ready(function() {
    $('.modal').modal();
    updateIpList()
    

    function updateIpList() {
        if ($('#ip-list').children('option').length > 0) {
            $('#ip-list').prop('disabled', false);
        } else {
            $('#ip-list').prop('disabled', true);
        }
        // Re-initialize the select element
        let selectInstance = M.FormSelect.getInstance($('#ip-list'));
        if (selectInstance) {
            selectInstance.destroy();
        }
        M.FormSelect.init($('#ip-list'));
    }
    
    
    
    $('#analysis-result').on('click', 'a', function() {
        let headerContent = $(this).data('value');
        if ($(this).next('.header-content').length > 0) {
            $(this).next('.header-content').remove();
        } else {
            $(this).after(`<div class="header-content">${headerContent}</div>`);
        }
    });
    


    if(window.location.pathname === "/sip_sniffer") {
        const socket = io.connect(`http://${document.domain}:${location.port}`);
        const ipList = [];
        let sipMessages = [];
        let startTime;
        let packetId = 0;
        const packetRowMap = {};
        
        $.get('/get_ports', function(data) {
            var ports = data.split(',');
            $('#port-list').val(ports);
            M.FormSelect.init($('#port-list'));
        });

        function generateSequenceDiagram(sipMessages) {
            const participants = new Set();
            let diagramText = '{ "signal": [\n';
        
            sipMessages.forEach((message, index) => {
                let parsedMessage = parseSipMessage(message);
                let from = parsedMessage.headers['From'] || parsedMessage.headers['from'];
                let to = parsedMessage.headers['To'] || parsedMessage.headers['to'];
        
                if (from && to) {
                    from = from.split(';')[0].replace(/<sip:/g, '').replace(/>/g, '');
                    to = to.split(';')[0].replace(/<sip:/g, '').replace(/>/g, '');
        
                    // Ensure participant IDs are unique
                    participants.add(from);
                    participants.add(to);
                }
            });
        
            // Create a mapping of unique participant names to participant IDs
            const participantMap = {};
            let participantIndex = 1;
            participants.forEach((participant) => {
                participantMap[participant] = `participant_${participantIndex}`;
                participantIndex++;
            });
        
            sipMessages.forEach((message, index) => {
                let parsedMessage = parseSipMessage(message);
                let from = parsedMessage.headers['From'] || parsedMessage.headers['from'];
                let to = parsedMessage.headers['To'] || parsedMessage.headers['to'];
        
                if (from && to) {
                    from = from.split(';')[0].replace(/<sip:/g, '').replace(/>/g, '');
                    to = to.split(';')[0].replace(/<sip:/g, '').replace(/>/g, '');
        
                    let method = parsedMessage.headers['CSeq'] ? parsedMessage.headers['CSeq'].split(' ')[1] : '';
        
                    if (method) {
                        let arrow = index % 2 === 0 ? '->>' : '>>';
                        diagramText += `["${participantMap[from].replace(/"/g, '\\"')}", "${participantMap[to].replace(/"/g, '\\"')}", "${arrow} ${method}"]`;
                        if (index < sipMessages.length - 1) {
                            diagramText += ',\n';
                        }
                    }
                }
            });
        
            diagramText += ']}';
        
            // Process WaveDrom to render the new diagram
            try {
                const diagramData = JSON.parse(diagramText);
                console.log('Diagram Data:', diagramData);
        
                // Ensure the DOM is ready
                document.addEventListener('DOMContentLoaded', function () {
                    // Remove existing diagram (if any)
                    const existingDiagram = document.querySelector('#sip-flow-result .wavedrom');
                    if (existingDiagram) {
                        existingDiagram.remove();
                    }
        
                    // Create a new div for the sequence diagram
                    const sequenceDiagramDiv = document.createElement('div');
                    sequenceDiagramDiv.className = 'wavedrom';
                    sequenceDiagramDiv.style.maxHeight = '500px'; // Adjust the height as needed
                    document.getElementById('sip-flow-result').appendChild(sequenceDiagramDiv);
        
                    // Generate the sequence diagram
                    WaveDrom.RenderWaveForm(diagramData, 'sip-flow-result', {
                        skin: 'default',
                        avoidAlias: true,
                        height: 200,
                    });
                });
            } catch (error) {
                console.error('Error generating sequence diagram:', error);
                console.log('Diagram Text:', diagramText);
            }
        }
        
        
        

        $('#sip-flow-analysis').click(function() {
            // Generate and display the sequence diagram
            generateSequenceDiagram(sipMessages);
        
            // Open the sequence diagram modal
            $('#sequenceDiagram').modal('open');
        });

        
         
        

    
        function parseSipMessage(message) {
            let lines = message.split('\n');
            let headers = {};
            let body = '';
        
            lines.forEach((line, index) => {
                if (line === '\r') {
                    body = lines.slice(index).join('\n');
                } else {
                    let parts = line.split(':');
                    let headerName = parts[0].trim();
                    let headerValue = parts.slice(1).join(':').trim();
                    headers[headerName] = headerValue;
                }
            });
        
            return { headers, body };
        }
        
        
        $('#header-analysis').click(function() {
            console.log('Header Analysis button clicked');
            let packetDetails = $('#packet-detail-box-content').text();
            let parsed = parseSipMessage(packetDetails);
            console.log(parsed);
        
            // Clear the previous analysis result
            $('#analysis-result').empty();
        
            // Populate the analysis result with parsed headers
            for (let header in parsed.headers) {
                let content = parsed.headers[header].replace(/</g, '&lt;').replace(/>/g, '&gt;');
                $('#analysis-result').append(`
                    <li>
                        <div class="collapsible-header"><b>${header}</b></div>
                        <div class="collapsible-body"><span>${content}</span></div>
                    </li>
                `);
            }
        
            // Initialize the collapsible
            $('.collapsible').collapsible();
        
            // Open the analysis result modal
            $('#analysis-modal').modal('open');
        });
        
        
        
        
        
        
        
    
        $('#add-ip-button').click(function() {
            let ip = $('#ip-input').val();
            console.log('IP:', ip);  // Check the IP value
            ipList.push(ip);
            $('#ip-list').append(new Option(ip, ip));
            console.log('IP List:', ipList);  // Check the IP list
            updateIpList();  // Update the IP list after adding an IP
        });

        socket.on('packet_sniffed', function(packetDetails) {
            // Exclude packets that only contain a newline
            if (packetDetails.trim() === '') {
                return;
            }

            // Exclude the IP addresses at the beginning of each packet
            let lines = packetDetails.split('\n');
            lines.splice(0, 1);
            packetDetails = lines.join('\n');

            let existingText = $('#packet-details').val();
            $('#packet-details').val(`${existingText}\n${packetDetails}`);
            packetRowMap[packetId] = packetDetails;
            sipMessages.push(packetDetails); 
            console.log('Added packet to sipMessages:', packetDetails);
            packetId++;
            M.textareaAutoResize($('#packet-details'));
        });

        socket.on('summary_updated', function(summary) {
            let rows = summary.split('\n').slice(1);
            rows.forEach(function(row, index) {
                let parts = row.split('\t\t');
                $('#summary-table tbody').append(`<tr id="row-${index}"><td>${parts[0]}</td><td>${parts[1]}</td><td>${parts[2]}</td></tr>`);
            });
        });

        let intervalId;

        $('#start-button').click(function() {
            let selectedIps = $('#ip-list').val();
            let selectedPorts = $('#port-input').val().split(',');
        
            // Validate target IP addresses and ports
            if (selectedIps.length === 0) {
                alert('Please enter at least one target IP address.');
                return;
            }
        
            if (!selectedPorts.every(port => /^\d+$/.test(port))) {
                alert('Invalid port format. Please enter valid ports separated by commas.');
                return;
            }
        
            // Set ports
            $.post('/set_ports', { 'ports[]': selectedPorts });
        
            $.post('/start', { 'target_ips[]': selectedIps }).fail(function() {
                alert('Unable to start sniffing. Please check your network connection and try again.');
            });
            $('#loading-spinner').show();
            startTime = Date.now();
            setInterval(function() {
                let elapsedSeconds = Math.floor((Date.now() - startTime) / 1000);
                $('#elapsed-time').text(`Elapsed time: ${elapsedSeconds} seconds`);
            }, 1000);
            $('#capturing-animation').show();
        });
        
        
        $('#stop-button').click(function() {
            $.post('/stop').fail(function() {
                alert('Unable to stop sniffing. Please check your network connection and try again.');
            });
            $('#loading-spinner').hide();
            $('#capturing-animation').hide();
            clearInterval(intervalId);
        });
        
        

        
        $('#set-ports-button').click(function() {
            var ports = $('#port-input').val().split(',');
            $.post('/set_ports', { 'ports[]': ports });
        });

        $('#theme-switch').click(function() {
            if ($('body').hasClass('light-mode')) {
                $('body').removeClass('light-mode').addClass('dark-mode');
                $(this).text('Switch to Light Mode');
            } else {
                $('body').removeClass('dark-mode').addClass('light-mode');
                $(this).text('Switch to Dark Mode');
            }
        });
        

        $('#summary-table tbody').on('dblclick', 'tr', function() {
            let rowId = $(this).attr('id').split('-')[1];
            let packetDetails = packetRowMap[rowId];
            packetDetails = packetDetails.replace(/</g, '&lt;').replace(/>/g, '&gt;');  // Escape < and >
            $('#packet-detail-box-content').html(packetDetails.replace(/\n/g, '<br>'));
            $('#packet-detail-box').addClass('open');

            generateSequenceDiagram(sipMessages);
        });
        

        $('#packet-detail-box-close').click(function() {
            $('#packet-detail-box').removeClass('open');
        });

        $('#clear-button').click(function() {
            $('#packet-details').val('');
            $('#summary-table tbody').empty();
            $('#packet-detail-box').removeClass('open');
        });
    }
    
});
