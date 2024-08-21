FROM public.ecr.aws/lambda/python:3.12

# Copy the function code and dependencies file into the container
COPY app.py ./
COPY requirements.txt ./

# Install the dependencies
RUN pip install -r requirements.txt

# Set the CMD to your handler (app.lambda_handler is the function entry point)
CMD ["app.lambda_handler"]
