import analyzeUrl from "../../services/analyze.service.js"

async function analyzeLink(req, res, next) {
    try {

        const { url } = req.body
        
        const result = analyzeUrl(url)
        console.log("result is" ,result)
        res.status(200).json({
            result: result
        })
    } catch (err) {
        next(err)
    }
}

export default analyzeLink