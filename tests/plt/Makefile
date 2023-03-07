

all:
	gcc ./overwrite-plt.c -o plt.out
	gcc ./overwrite-plt.c -o noplt.out -DOVERWRITE=1
	@echo "objdump -d {plt.out,noplt.out}"

clean:
	rm *.out -f
