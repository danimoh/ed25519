# If you do not have emcc in your path, navigate to your emscripten folder, type
# ./emsdk acivate
# and then
# source ./emsdk_env.sh

# Note that compilation with EMCC_WASM_BACKEND=1 requires a wasm enabled LLVM build and LLVM_ROOT in
# /home/.emscripten has to point to that build.

# However: The emcc wasm backend is not production ready yet. In my tests, it didn't work as when objects
# or structs are defined as local variables, the compiler puts them on the stack, where they are not
# accessible for wasm (as of https://github.com/WebAssembly/design/blob/master/Nondeterminism.md,
# memory access out of bounds gets thrown).

# compile using emscripten.
COMPILE_EMCC = emcc -c -O3	# Command to compile a module from .c to .o
LINK_EMCC =	emcc -O3				# Command to link a program

emcc:
	$(COMPILE_EMCC) src/fe.c -o fe.o
	$(COMPILE_EMCC) src/ge.c -o ge.o
	$(COMPILE_EMCC) src/keypair.c -o keypair.o
	$(COMPILE_EMCC) src/sc.c -o sc.o
	$(COMPILE_EMCC) src/sha512.c -o sha512.o
	$(COMPILE_EMCC) src/sign.c -o sign.o
	$(COMPILE_EMCC) src/verify.c -o verify.o
	$(COMPILE_EMCC) src/memory.c -o memory.o

	# compile to asm.js (might want to add -s ONLY_MY_CODE=1, see https://github.com/kripken/emscripten/issues/3955)
	$(LINK_EMCC) fe.o ge.o keypair.o sc.o sha512.o sign.o verify.o memory.o \
		-s EXPORTED_FUNCTIONS='["_ed25519_sign","_ed25519_verify","_get_static_memory_start","_get_static_memory_size","_ed25519_public_key_derive"]' \
		-s NO_EXIT_RUNTIME=1 -s MODULARIZE=1 -s EXPORT_NAME="'ED25519_HANDLER'" \
		-s LIBRARY_DEPS_TO_AUTOEXPORT='[]' -s DEFAULT_LIBRARY_FUNCS_TO_INCLUDE="[]" -s EXPORTED_RUNTIME_METHODS='[]' \
		-s NO_FILESYSTEM=1 -s DISABLE_EXCEPTION_CATCHING=1 -s ELIMINATE_DUPLICATE_FUNCTIONS=1 \
		--closure 1 \
		-o dist/ed25519-asm.js
	
	# compile to wasm
	$(LINK_EMCC) fe.o ge.o keypair.o sc.o sha512.o sign.o verify.o memory.o \
		-s EXPORTED_FUNCTIONS='["_ed25519_sign","_ed25519_verify","_get_static_memory_start","_get_static_memory_size","_ed25519_public_key_derive"]' \
		-s NO_EXIT_RUNTIME=1 -s MODULARIZE=1 -s EXPORT_NAME="'ED25519_HANDLER'" \
		-s LIBRARY_DEPS_TO_AUTOEXPORT='[]' -s DEFAULT_LIBRARY_FUNCS_TO_INCLUDE="[]" -s EXPORTED_RUNTIME_METHODS='[]' \
		-s NO_FILESYSTEM=1 -s DISABLE_EXCEPTION_CATCHING=1 \
		-s WASM=1 --closure 1 \
		-o dist/ed25519-wasm.js
	
	# Compilation directly to .wasm, not via first asm.js
	# See https://github.com/kripken/emscripten/wiki/New-WebAssembly-Backend
	# This requires an llvm build with enabled WebAssembly support, see https://gist.github.com/yurydelendik/4eeff8248aeb14ce763e (see comment by puzrin for a much smaller build).
	# The llvm backend must then be specified in /home/.emscripten as LLVM_ROOT.
	# If you get the error "Expected wasm_compiler_rt.a to already be built", create a build first without -s WASM=1 and without EMCC_WASM_BACKEND=1.
	# Note that EMCC still outputs a small .js file. This however only contains side module logic and can be ignored.
	#EMCC_WASM_BACKEND=1 $(LINK_EMCC) fe.o ge.o keypair.o sc.o sha512.o sign.o verify.o memory.o \
	#	-s EXPORTED_FUNCTIONS='["_ed25519_sign","_ed25519_verify","_get_static_memory_start","_get_static_memory_size"]' \
	#	-s NO_EXIT_RUNTIME=1 -s MODULARIZE=1 -s EXPORT_NAME="'ED25519'" \
	#	-s LIBRARY_DEPS_TO_AUTOEXPORT='[]' -s DEFAULT_LIBRARY_FUNCS_TO_INCLUDE="[]" -s EXPORTED_RUNTIME_METHODS='[]' \
	#	-s NO_FILESYSTEM=1 -s DISABLE_EXCEPTION_CATCHING=1 \
	#	-s WASM=1 -s SIDE_MODULE=1 \
	#	-o dist/ed25519-wasm.wasm

	rm -f *.o

clean:
	rm -f *.o dist/*-asm.data dist/*-asm.js dist/*-asm.html dist/*-wasm.data dist/*-wasm.html dist/*-wasm.js dist/*-wasm.wasm dist/*.mem dist/*.asm.js
