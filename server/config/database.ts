import mongoose from 'mongoose'

const URI = process.env.MONGODB_URL 

mongoose.connect(`${URI}`, {
  useCreateIndex: true,
  useNewUrlParser: true,
  useUnifiedTopology: true
}, (err) => {
  if(err) throw err;
  console.log('Mongodb connection')
})