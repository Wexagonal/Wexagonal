const gres = (body, config) => {
    config = config || {}
    return {
        body: typeof (body) == "object" ? JSON.stringify(body) : body,
        status: config.status ? config.status : 200,
        headers: {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*"
        }
    }

}
export default gres