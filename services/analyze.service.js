
const url = "http://checkurl.staging.phishtank.com/checkurl/"

function analyzeUrl(url) {
    // const data = {url: url, format: 'json'}
    let result
    fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
            url: url,
            format: 'json'
        })
    }).then(response => response.json())
    .then(data => { result = data })
    .catch(error => console.error('Error:', error))

    return result

}


export default analyzeUrl

