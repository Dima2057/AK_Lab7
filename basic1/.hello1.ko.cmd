cmd_/home/dmytro/AK2_Lab7/basic1/hello1.ko := ccache arm-eabi-ld -r  -EL -T ./scripts/module-common.lds -T ./arch/arm/kernel/module.lds  --build-id  -o /home/dmytro/AK2_Lab7/basic1/hello1.ko /home/dmytro/AK2_Lab7/basic1/hello1.o /home/dmytro/AK2_Lab7/basic1/hello1.mod.o ;  true