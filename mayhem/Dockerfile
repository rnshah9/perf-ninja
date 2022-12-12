FROM --platform=linux/amd64 ubuntu:22.04 as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential cmake libbenchmark-dev clang

COPY . /repo
WORKDIR /repo/labs/memory_bound/loop_interchange_2/build
RUN cmake .. -DCMAKE_BUILD_TYPE=Release
RUN make -j8
RUN clang++ /repo/mayhem/fuzz_solution.cpp /repo/labs/core_bound/compiler_intrinsics_2/solution.cpp -fsanitize=fuzzer,address -I /repo/labs/core_bound/ -o /fuzz

FROM ubuntu:22.04 as package
RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y libbenchmark-dev
COPY --from=builder /repo/labs/memory_bound/loop_interchange_2/build/lab /
COPY --from=builder /fuzz /fuzz_solution
