   # 使用 Python 3.8 的精简版作为基础镜像
   FROM python:3.9

   # 设置工作目录
   WORKDIR /app

   # 复制当前目录下的所有文件到工作目录中
   COPY . /app

   # 安装 Python 依赖
   RUN pip install --no-cache-dir -r requirements.txt

   # 使用 Gunicorn 运行 Flask 应用
   CMD ["gunicorn", "-w", "4", "-b", "127.0.0.1:8000", "app:app"]