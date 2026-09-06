import axios from 'axios'

export const analyzeEvidence = async (file, text) => {
  const form = new FormData()
  if (file) form.append('file', file)
  if (text) form.append('text', text)
  const { data } = await axios.post('http://localhost:8000/analyze', form)
  return data
}