FROM radare/radare2:latest

USER root
WORKDIR /app
RUN apt update && apt-get install -y unzip curl openjdk-21-jdk
RUN curl -Lo apktool.jar https://github.com/iBotPeaches/Apktool/releases/download/v2.10.0/apktool_2.10.0.jar && \
    curl -Lo build-tools.zip https://dl.google.com/android/repository/build-tools_r34-linux.zip && \
    curl -Lo platform-tools-latest-linux.zip https://dl.google.com/android/repository/platform-tools-latest-linux.zip

RUN unzip build-tools.zip && unzip platform-tools-latest-linux.zip

COPY . .
CMD ["./patch.sh"]
