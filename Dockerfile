FROM radare/radare2:latest

USER root
WORKDIR /app
RUN apt update && apt-get install --no-install-recommends -y unzip curl openjdk-21-jdk git build-essential qmake6-bin qmake6
RUN curl -Lo apktool.jar https://github.com/iBotPeaches/Apktool/releases/download/v2.10.0/apktool_2.10.0.jar && \
    curl -Lo build-tools.zip https://dl.google.com/android/repository/build-tools_r34-linux.zip && \
    curl -Lo platform-tools-latest-linux.zip https://dl.google.com/android/repository/platform-tools-latest-linux.zip \
    rm -rf /var/lib/apt/lists/*
RUN unzip build-tools.zip && unzip platform-tools-latest-linux.zip && rm -rf build-tools.zip platform-tools-latest-linux.zip

# install protodec for decompiling proto files from the so files
RUN git clone https://github.com/schdub/protodec --depth=1
WORKDIR protodec
RUN qmake6 . && make
WORKDIR /app

COPY . .
CMD ["./patch.sh"]
