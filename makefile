CCC ?=gcc
CC=$(CCC)
INCLUDES=-I./shared/include -I./kernel -I./consola -I./cpu -I./memoria
CFLAGS=$(INCLUDES) -g -Wall -fno-strict-aliasing -Wno-incompatible-pointer-types

LIBS=-lcommons -lpthread -lreadline -lcunit -lrt -lm

MODULES=cpu consola kernel memoria

all: $(MODULES)

define MAKE_TARGETS

.SECONDEXPANSION:

name=$(strip $1)
# Crear el directorio de salida. Los .o dependen de esta regla
$(strip $1)/obj:
	mkdir $$@

# La regla ej. kernel va a kernel/kernel el path al binario
$(strip $1): $(strip $1)/$(strip $1)
# El binario compila $@ que es la regla osea su path, con las dependencias pasadas al compilador
# Y depende de todos los archivos .c del directorio ej kernel/*.c substituidos como kernel/obj/*.o
$(strip $1)/$(strip $1): $(strip $1)/obj/$(strip $1)_shared_utils.o $(patsubst $(strip $1)/%.c,$(strip $1)/obj/%.o,$(wildcard $(strip $1)/*.c))
	$(CC) -o $$@ $$^ $(CFLAGS) $(LIBS)

# Los .o compilan al /c gurdando el objeto el $1/obj ej. kernel/obj
$(strip $1)/obj/%.o: $(strip $1)/%.c $(strip $1)/obj
	$(CC) -c -o $$@ $$< $(CFLAGS)

# La shared se compila especificamente para este modulo en $1/obj/$1_shared_utils.o
# Ej. kernel/obj/kernel_shared_utils.o
# Esto para poder compilar en paralelo sin problemas.
$(strip $1)/obj/$(strip $1)_shared_utils.o: $(strip $1)/obj
	$(CC) -c -o $$@ shared/shared_utils.c $(CFLAGS)

endef
$(foreach module_name, $(MODULES), $(eval $(call MAKE_TARGETS, $(module_name))))

.PHONY: clean

clean:
	rm -f **/*.o **/**/*.o ./kernel/kernel ./memoria/memoria ./cpu/cpu ./consola/consola

list:
	@LC_ALL=C $(MAKE) -pRrq -f $(lastword $(MAKEFILE_LIST)) : 2>/dev/null | awk -v RS= -F: '/^# File/,/^# Finished Make data base/ {if ($$1 !~ "^[#.]") {print $$1}}' | sort | egrep -v -e '^[^[:alnum:]]' -e '^$@$$'