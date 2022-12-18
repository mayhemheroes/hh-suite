FROM --platform=linux/amd64 debian:stable-slim as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential cmake clang

COPY . /repo
WORKDIR /repo/build 
RUN cmake .. -DCMAKE_INSTALL_PREFIX=/install -DCMAKE_BUILD_TYPE=Release -DHAVE_SSE2=1
RUN make -j8
RUN make install
RUN clang++ /repo/mayhem/fuzz_uprstr.cpp -fsanitize=fuzzer,address -I /repo/src/ -I /repo/lib/simd -I /repo/lib/simde/ /repo/build/src/libHH_OBJECTS.a -o /fuzz

FROM debian:stable-slim as package
RUN apt-get update
# RUN DEBIAN_FRONTEND=noninteractive apt-get install -y libgomp1
RUN apt-get update && apt-get install -y \
    libstdc++6 libgomp1

COPY --from=builder /install /usr/local/hh-suite
COPY --from=builder /fuzz /fuzz_uprstr
ENV HHLIB=/usr/local/hh-suite
ENV PATH="/usr/local/hh-suite/bin:/usr/local/hh-suite/scripts:${PATH}"
