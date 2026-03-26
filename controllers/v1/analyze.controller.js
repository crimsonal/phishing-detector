import analyzeUrl from "../../services/analyze.service.js"

async function analyzeLink(req, res, next) {
    try {

        const { url } = req.body
        
        if (!url) {
            return res.status(400).json({ error: "url is required in request body" });
        }

        const result = await analyzeUrl(url)
        console.log("result is" ,result)
        res.status(200).json({
           result
        })
    } catch (err) {
        next(err)
    }
}

export default analyzeLink