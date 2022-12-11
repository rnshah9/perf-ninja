FROM --platform=linux/amd64 ubuntu:22.04 as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential cmake libbenchmark-dev

COPY . /repo
WORKDIR /repo/labs/memory_bound/loop_interchange_2/build
RUN cmake .. -DCMAKE_BUILD_TYPE=Release
RUN make -j8

FROM ubuntu:22.04 as package
RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y libbenchmark-dev
COPY --from=builder /repo/labs/memory_bound/loop_interchange_2/build/lab /
