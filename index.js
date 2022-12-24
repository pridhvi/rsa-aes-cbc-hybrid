
function encryptFile() {
    var file = window.document.getElementById('enc-file'),
        reader = new FileReader();
    console.log(file.files[0]);
    console.log('TESTING');

    reader.onload = function(e) {
        var data = e.target.result,
            iv = crypto.getRandomValues(new Uint8Array(16));
      
        crypto.subtle.generateKey({ 'name': 'AES-GCM', 'length': 128 }, false, ['encrypt', 'decrypt'])
            .then(key => {
                crypto.subtle.encrypt({ 'name': 'AES-GCM', iv }, key, data)

                var keyByteArray = new Uint8Array(key);
                var downloadEncKey = window.document.getElementById('download-enc-key-button');
                downloadEncKey.href = window.URL.createObjectURL(new Blob([keyByteArray], { type: 'application/octet-stream' }));
                downloadEncKey.download = file.files[0].name + '.key';

                var downloadEncKeyMessage = window.document.getElementById('download-enc-key-message');
                downloadEncKeyMessage.textContent = 'Note: You will need this key to decrypt the file!';

                var downloadEncKeyName = window.document.getElementById('download-enc-key-name');
                downloadEncKeyName.textContent = file.files[0].name + '.key';
            })
            .then(encryptedFile => {
                var byteArray = new Uint8Array(encryptedFile);
                var downloadEncFile = window.document.getElementById('download-enc-file-button');

                downloadEncFile.href = window.URL.createObjectURL(new Blob([byteArray], { type: 'application/octet-stream' }));
                downloadEncFile.download = file.files[0].name + '.encrypted';

                var downloadEncFileMessage = window.document.getElementById('download-enc-file-message');
                downloadEncFileMessage.textContent = 'Your encrypted file is ready!';

                var downloadEncFileName = window.document.getElementById('download-enc-file-name');
                downloadEncFileName.textContent = file.files[0].name + '.encrypted';
            })
            .catch(console.error);
    }

    reader.readAsArrayBuffer(file.files[0]);
}