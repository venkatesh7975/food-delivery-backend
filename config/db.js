import mongoose from "mongoose";

export const connectDB = async () => {
  await mongoose
    .connect(
      "mongodb+srv://mvenky9100:Venkatesh7975@food-delivery.w6vbo.mongodb.net/food?retryWrites=true&w=majority&appName=food-delivery"
    )
    .then(() => console.log("DB Connected"));
};
