import axios from 'axios'

const client = axios.create({
  baseURL: import.meta.env.FASTAPI_URL,
})

export default client
