$(document).ready(function() {

    $.ajax({
        url: '/get_uploaded_files',
        type: 'GET',
        success: function(data) {
            data.forEach(function(file) {
                $('#uploaded-files').append(`<li class="collection-item avatar"><i class="material-icons circle blue">insert_drive_file</i><a class="title" href="${file[1]}" target="_blank">${file[0]}</a></li>`);
            });
        },
        error: function() {
            alert('Unable to retrieve uploaded files. Please check your network connection and try again.');
        }
    });
    
    console.log('JavaScript file loaded');
    $('#upload-form').submit(function(e) {
        e.preventDefault();
        console.log('Form submitted');  // Check if the form submission event is being triggered
        let file = $('#documentationUpload')[0].files[0];
        console.log(file);  // Check if the file is being correctly identified
        let formData = new FormData();
        formData.append('file', file);
        for (var pair of formData.entries()) {
            console.log(pair[0]+ ', ' + pair[1]);  // Check if the form data is correct
        }
        $.ajax({
            url: '/upload',
            type: 'POST',
            data: formData,
            processData: false,
            contentType: false,
            success: function(data) {
                $('#uploaded-files').append(`<li class="collection-item avatar"><i class="material-icons circle blue">insert_drive_file</i><a class="title" href="${data.url}" target="_blank">${file.name}</a></li>`);
                $('.file-path.validate').val('');  // clear the file name from the text input
            },            
            error: function() {
                alert('Unable to upload file. Please check your network connection and try again.');
            }
        });
    });
    


    $('#theme-switch').click(function() {
        $('body').toggleClass('dark-mode');
    });



});
