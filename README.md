# createkeystorefips

Crear Keystore Bouncy Castle Fips

La siguiente aplicación crea un keystore de tipo BCFKS.

Además crea un certificado X509 v3 y envía una solicitud CSR a un servicio para la creación de la clave pública.

Se recibe el response como PKCS7 y se almacena en el keystore el certificado con su clave privada

# Requisitos

- Maven

- JDK 1.8 o superior

- git

# Pasos instalación

- clonar el repositorio

- git clone https://github.com/jgrateron/createkeystorefips.git

- entrar a la carpeta del proyecto

- cd createkeystorefips

- compilar el proyecto

- mvn package

- crear las variables de entorno y colocar sus valores

- export KEYSTORE_PASSWORD=

- export SERVICE_URL=

- export SERVICE_AUTHORIZATION=

- Ejecutar la aplicación

- java -jar target/createkeystorefips-0.0.1-SNAPSHOT.jar

- si todo está correcto, se debió crear el archivo keystore.bks 

- se puede visualizar el contenido del almacén usando la aplicación KeyStore Explorer


# Consideraciones

- Bouncy Castle Fips hace un uso intensivo de entropía, lo que la aplicación pueda quedar congelada mientras el SO crea más.

- Bouncy Castle Fips no toma en cuenta el parámetro -Djava.security.egd, el cual permite cambiar donde se obtiene la entropía.

- Bouncy Castle Fips verifica internamente si hubo cambios en su jar, entonces la aplicación no iniciará si existe cambios en sus librerías.

- BC y BC Fips no pueden estar dentro del mismo proyecto ya que algunas clases se solapan porque tienen los mismos nombres y por lo tanto la aplicación no funciona.


